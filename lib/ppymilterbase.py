# $Id$
# ==============================================================================
# Copyright 2008 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ==============================================================================
#
# Pure python milter interface (does not use libmilter.a).
# Handles parsing of milter protocol data (e.g. over a network socket)
# and provides standard arguments to the callbacks in your handler class.
#
# For details of the milter protocol see:
#  http://search.cpan.org/src/AVAR/Sendmail-PMilter-0.96/doc/milter-protocol.txt
#

__author__ = 'Eric DeFriez'

import binascii
import logging
import os
import socket
import struct
import sys


MILTER_VERSION = 2 # Milter version we know we claim to speak (from pmilter)

# Potential milter command codes and their corresponding PpyMilter callbacks.
# From sendmail's include/libmilter/mfdef.h
COMMANDS = {
  'A': 'Abort',      # SMFIC_ABORT   # "Abort"
  'B': 'Body',       # SMFIC_BODY    # "Body chunk"
  'C': 'Connect',    # SMFIC_CONNECT # "Connection information"
  'D': 'Macro',      # SMFIC_MACRO   # "Define macro"
  'E': 'EndBody',    # SMFIC_BODYEOB # "final body chunk (End)"
  'H': 'Helo',       # SMFIC_HELO    # "HELO/EHLO"
  'L': 'Header',     # SMFIC_HEADER  # "Header"
  'M': 'MailFrom',   # SMFIC_MAIL    # "MAIL from"
  'N': 'EndHeaders', # SMFIC_EOH     # "EOH"
  'O': 'OptNeg',     # SMFIC_OPTNEG  # "Option negotation"
  'R': 'RcptTo',     # SMFIC_RCPT    # "RCPT to"
  'Q': 'Quit',       # SMFIC_QUIT    # "QUIT"
  'T': 'Data',       # SMFIC_DATA    # "DATA"
  'U': 'Unknown',    # SMFIC_UNKNOWN # "Any unknown command"
  }

# To register/mask callbacks during milter protocol negotiation with sendmail.
# From sendmail's include/libmilter/mfdef.h
NO_CALLBACKS = 127  # (all seven callback flags set: 1111111)
CALLBACKS = {
  'OnConnect':    1,  # 0x01 SMFIP_NOCONNECT # Skip SMFIC_CONNECT
  'OnHelo':       2,  # 0x02 SMFIP_NOHELO    # Skip SMFIC_HELO
  'OnMailFrom':   4,  # 0x04 SMFIP_NOMAIL    # Skip SMFIC_MAIL
  'OnRcptTo':     8,  # 0x08 SMFIP_NORCPT    # Skip SMFIC_RCPT
  'OnBody':       16, # 0x10 SMFIP_NOBODY    # Skip SMFIC_BODY
  'OnHeader':     32, # 0x20 SMFIP_NOHDRS    # Skip SMFIC_HEADER
  'OnEndHeaders': 64, # 0x40 SMFIP_NOEOH     # Skip SMFIC_EOH
  }

# Acceptable response commands/codes to return to sendmail (with accompanying
# command data).  From sendmail's include/libmilter/mfdef.h
RESPONSE = {
    'ADDRCPT'    : '+', # SMFIR_ADDRCPT    # "add recipient"
    'DELRCPT'    : '-', # SMFIR_DELRCPT    # "remove recipient"
    'ACCEPT'     : 'a', # SMFIR_ACCEPT     # "accept"
    'REPLBODY'   : 'b', # SMFIR_REPLBODY   # "replace body (chunk)"
    'CONTINUE'   : 'c', # SMFIR_CONTINUE   # "continue"
    'DISCARD'    : 'd', # SMFIR_DISCARD    # "discard"
    'CONNFAIL'   : 'f', # SMFIR_CONN_FAIL  # "cause a connection failure"
    'ADDHEADER'  : 'h', # SMFIR_ADDHEADER  # "add header"
    'INSHEADER'  : 'i', # SMFIR_INSHEADER  # "insert header"
    'CHGHEADER'  : 'm', # SMFIR_CHGHEADER  # "change header"
    'PROGRESS'   : 'p', # SMFIR_PROGRESS   # "progress"
    'QUARANTINE' : 'q', # SMFIR_QUARENTINE # "quarentine"
    'REJECT'     : 'r', # SMFIR_REJECT     # "reject"
    'SETSENDER'  : 's', # v3 only?
    'TEMPFAIL'   : 't', # SMFIR_TEMPFAIL   # "tempfail"
    'REPLYCODE'  : 'y', # SMFIR_REPLYCODE  # "reply code etc"
    }


def printchar(char):
  """Useful debugging function for milter developers."""
  print ('char: %s [qp=%s][hex=%s][base64=%s]' %
         (char, binascii.b2a_qp(char), binascii.b2a_hex(char),
          binascii.b2a_base64(char)))


class PpyMilterException(Exception):
  """Parent of all other PpyMilter exceptions.  Subclass this: do not
  construct or catch explicitly!"""


class PpyMilterPermFailure(PpyMilterException):
  """Milter exception that indicates a perment failure."""


class PpyMilterTempFailure(PpyMilterException):
  """Milter exception that indicates a temporary/transient failure."""


class PpyMilterCloseConnection(PpyMilterException):
  """Exception that indicates the server should close the milter connection."""


class PpyMilterDispatcher:
  """Dispatcher class for a milter server.  This class accepts entire
  milter commands as a string (command character + binary data), parses
  the command and binary data appropriately and invokes the appropriate
  callback function in a milter_class instance.  One PpyMilterDispatcher
  per socket connection.  One milter_class instance per PpyMilterDispatcher
  (per socket connection)."""

  def __init__(self, milter_class):
    """Construct a PpyMilterDispatcher and create a private
    milter_class instance.

    Args:
      milter_class: A class (not an instance) that handles callbacks for
                    milter commands (e.g. a child of the PpyMilter class).
    """
    self.__milter = milter_class()


  def Dispatch(self, data):
    """Callback function for the milter socket server to handle a single
    milter command.  Parses the milter command data, invokes the milter
    handler, and formats a suitable response for the server to send
    on the socket.

    Args:
      data: A (binary) string (consisting of a command code character
            followed by binary data for that command code).

    Returns:
      A binary string to write on the socket and return to sendmail.  The
      string typically consists of a RESPONSE[] command character then
      some response-specific protocol data.

    Raises:
      PpyMilterCloseConnection: Indicating the (milter) connection should
                                be closed.
    """
    (cmd, data) = (data[0], data[1:])
    try:
      if cmd not in COMMANDS:
        logging.warn('Unknown command code: "%s" ("%s")', cmd, data)
        return RESPONSE['CONTINUE']
      command = COMMANDS[cmd]
      parser_callback_name = '_Parse%s' % command
      handler_callback_name = 'On%s' % command

      if not hasattr(self, parser_callback_name):
        logging.error('No parser implemented for "%s"', command)
        return RESPONSE['CONTINUE']

      if not hasattr(self.__milter, handler_callback_name):
        logging.warn('Unimplemented command: "%s" ("%s")', command, data)
        return RESPONSE['CONTINUE']

      parser = getattr(self, parser_callback_name)
      callback = getattr(self.__milter, handler_callback_name)
      args = parser(cmd, data)
      response_tuple = callback(*args)
      try:
        (code, response) = response_tuple
        return '%s%s' % (code, response)
      except TypeError, e:
        return None # handler didn't return tuple: don't respond to the command
    except PpyMilterTempFailure, e:
      logging.info('Temp Failure: %s', str(e))
      return RESPONSE['TEMPFAIL']
    except PpyMilterPermFailure, e:
      logging.info('Perm Failure: %s', str(e))
      return RESPONSE['REJECT']
    return RESPONSE['CONTINUE']

  def _ParseOptNeg(self, cmd, data):
    """Parse the 'OptNeg' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple consisting of:
        cmd: The single character command code representing this command.
        ver: The protocol version we support.
        actions: Bitmask of the milter actions we may perform
                 (see "PpyMilter.ACTION_*").
        protocol: Bitmask of the callback functions we are registering.

    """
    (ver, actions, protocol) = struct.unpack('!III', data)
    return (cmd, ver, actions, protocol)

  def _ParseMacro(self, cmd, data):
    """Parse the 'Macro' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple consisting of:
        cmd: The single character command code representing this command.
        macro: The single character command code this macro is for.
        data: A list of strings alternating between name, value of macro.
    """
    (macro, data) = (data[0], data[1:])
    return (cmd, macro, data.split('\0'))

  def _ParseConnect(self, cmd, data):
    """Parse the 'Connect' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple (cmd, hostname, family, port, address) where:
        cmd: The single character command code representing this command.
        hostname: The hostname that originated the connection to the MTA.
        family: Address family for connection (see sendmail libmilter/mfdef.h).
        port: The network port if appropriate for the connection.
        address: Remote address of the connection (e.g. IP address).
    """
    (hostname, data) = data.split('\0', 1)
    family = struct.unpack('c', data[0])[0]
    port = struct.unpack('!H', data[1:3])[0]
    address = data[3:]
    return (cmd, hostname, family, port, address)

  def _ParseHelo(self, cmd, data):
    """Parse the 'Helo' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple (cmd, data) where:
        cmd: The single character command code representing this command.
        data: TODO: parse this better
    """
    return (cmd, data)

  def _ParseMailFrom(self, cmd, data):
    """Parse the 'MailFrom' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple (cmd, mailfrom, esmtp_info) where:
        cmd: The single character command code representing this command.
        mailfrom: The MAIL From email address.
        esmtp_info: Extended SMTP (esmtp) info as a list of strings.
    """
    (mailfrom, esmtp_info) = data.split('\0', 1)
    return (cmd, mailfrom, esmtp_info.split('\0'))

  def _ParseRcptTo(self, cmd, data):
    """Parse the 'RcptTo' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple (cmd, rcptto, emstp_info) where:
        cmd: The single character command code representing this command.
        rcptto: The RCPT To email address.
        esmtp_info: Extended SMTP (esmtp) info as a list of strings.
    """
    (rcptto, esmtp_info) = data.split('\0', 1)
    return (cmd, rcptto, esmtp_info.split('\0'))

  def _ParseHeader(self, cmd, data):
    """Parse the 'Header' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple (cmd, key, val) where:
        cmd: The single character command code representing this command.
        key: The name of the header.
        val: The value/data for the header.
    """
    (key, val) = data.split('\0', 1)
    return (cmd, key, val)

  def _ParseEndHeaders(self, cmd, data):
    """Parse the 'EndHeaders' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple (cmd) where:
        cmd: The single character command code representing this command.
    """
    return (cmd)

  def _ParseBody(self, cmd, data):
    """Parse the 'Body' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple (cmd, data) where:
        cmd : The single character command code representing this command.
        data: TODO: parse this better
    """
    return (cmd, data)

  def _ParseEndBody(self, cmd, data):
    """Parse the 'EndBody' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple (cmd, data) where:
        cmd: The single character command code representing this command.
        data: TODO: parse this better
    """
    return (cmd, data)

  def _ParseQuit(self, cmd, data):
    """Parse the 'Quit' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple (cmd) where:
        cmd: The single character command code representing this command.
    """
    return (cmd)


class PpyMilter:
  """Pure python milter handler base class.  Inherit from this class
  and override any On*() commands you would like your milter to handle.
  Register any actions your milter may perform using the Can*() functions
  during your __init__() (after calling PpyMilter.__init()__!) to ensure
  your milter's actions are accepted.

  Pass a reference to your handler class to a python milter socket server
  (e.g. AsyncPpyMilterServer) to create a stand-alone milter
  process than invokes your custom handler.
  """

  # Actions we tell sendmail we may perform
  # PpyMilter users invoke self.CanFoo() during their __init__()
  # to toggle these settings.
  ACTION_ADDHDRS    = 1  # 0x01 SMFIF_ADDHDRS    # Add headers
  ACTION_CHGBODY    = 2  # 0x02 SMFIF_CHGBODY    # Change body chunks
  ACTION_ADDRCPT    = 4  # 0x04 SMFIF_ADDRCPT    # Add recipients
  ACTION_DELRCPT    = 8  # 0x08 SMFIF_DELRCPT    # Remove recipients
  ACTION_CHGHDRS    = 16 # 0x10 SMFIF_CHGHDRS    # Change or delete headers
  ACTION_QUARENTINE = 32 # 0x20 SMFIF_QUARANTINE # Quarantine message

  def __init__(self):
    """Construct a PpyMilter object.  Sets callbacks and registers
    callbacks.  Make sure you call this directly "PpyMilter.__init__(self)"
    at the beginning of your __init__() if you override the class constructor!

    """
    self.__actions = 0
    self.__protocol = NO_CALLBACKS
    for (callback, flag) in CALLBACKS.iteritems():
      if hasattr(self, callback):
        self.__protocol &= ~flag

  def Accept(self):
    """Create an 'ACCEPT' response to return to the milter dispatcher."""
    return (RESPONSE['ACCEPT'], '')

  def Reject(self):
    """Create a 'REJECT' response to return to the milter dispatcher."""
    return (RESPONSE['REJECT'], '')

  def Discard(self):
    """Create a 'DISCARD' response to return to the milter dispatcher."""
    return (RESPONSE['DISCARD'], '')

  def TempFail(self):
    """Create a 'TEMPFAIL' response to return to the milter dispatcher."""
    return (RESPONSE['TEMPFAIL'], '')

  def Continue(self):
    """Create an '' response to return to the milter dispatcher."""
    return (RESPONSE['CONTINUE'], '')

  def CustomReply(self, code, text):
    """Create a 'REPLYCODE' (custom) response to return to the milter
    dispatcher.

    Args:
      code: Integer or digit string (should be \d\d\d).  NOTICE: A '421' reply
            code will cause sendmail to close the connection after responding!
            (https://www.sendmail.org/releases/8.13.0.html)
      text: Code reason/explaination to send to the user.
    """
    return (RESPONSE['REPLYCODE'], '%s %s\0' % (code, text))

  # you probably should not be overriding this  :-p
  def OnOptNeg(self, cmd, ver, actions, protocol):
    """Callback for the 'OptNeg' (option negotiation) milter command.
    Shouldn't be necessary to override (don't do it unless you
    know what you're doing).

    Option negotation is based on:
    (1) Command callback functions defined by your handler class.
    (2) Stated actions your milter may perform by invoking the
        "self.CanFoo()" functions during your milter's __init__().
    """
    out = struct.pack('!III', MILTER_VERSION,
                      self.__actions & actions,
                      self.__protocol & protocol)
    return (cmd, out)

  def OnMacro(self, cmd, macro_cmd, data):
    """Callback for the 'Macro' milter command: no response required."""
    return None

  def OnQuit(self, cmd):
    """Callback for the 'Quit' milter command: close the milter connection.

    The only logical response is to ultimately raise a
    PpyMilterCloseConnection() exception.
    """
    raise PpyMilterCloseConnection('received quit command')

  # Call these from __init__() (after calling PpyMilter.__init__()  :-p
  # to tell sendmail you may perform these actions
  # (otherwise performing the actions may fail).
  def CanAddHeaders(self):
    """Register that our milter may perform the action 'ADDHDRS'."""
    self.__actions |= self.ACTION_ADDHDRS

  def CanChangeBody(self):
    """Register that our milter may perform the action 'CHGBODY'."""
    self.__actions |= self.ACTION_CHGBODY

  def CanAddRecipient(self):
    """Register that our milter may perform the action 'ADDRCPT'."""
    self.__actions |= self.ACTION_ADDRCPT

  def CanDeleteRecipient(self):
    """Register that our milter may perform the action 'DELRCPT'."""
    self.__actions |= self.ACTION_DELRCPT

  def CanChangeHeaders(self):
    """Register that our milter may perform the action 'CHGHDRS'."""
    self.__actions |= self.ACTION_CHGHDRS

  def CanQuarentine(self):
    """Register that our milter may perform the action 'QUARENTINE'."""
    self.__actions |= self.ACTION_QUARENTINE

#!/usr/bin/python2.4
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
# Asynchronous and threaded socket servers for the sendmail milter protocol.
#
# Example usage:
#"""
#   import asyncore
#   import ppymilterserver
#   import ppymilterbase
#
#   class MyHandler(ppymilterbase.PpyMilter):
#     def OnMailFrom(...):
#       ...
#   ...
#
#   # to run async server
#   ppymilterserver.AsyncPpyMilterServer(port, MyHandler)
#   asyncore.loop()
#
#   # to run threaded server
#   ppymilterserver.ThreadedPpyMilterServer(port, MyHandler)
#   ppymilterserver.loop()
#"""
#

__author__ = 'Eric DeFriez'

import asynchat
import asyncore
import binascii
import logging
import os
import socket
import SocketServer
import struct
import sys
import time

import ppymilterbase


MILTER_LEN_BYTES = 4  # from sendmail's include/libmilter/mfdef.h


class AsyncPpyMilterServer(asyncore.dispatcher):
  """Asynchronous server that handles connections from
  sendmail over a network socket using the milter protocol.
  """

  # TODO: allow network socket interface to be overridden
  def __init__(self, port, milter_class, max_queued_connections=1024):
    """Constructs an AsyncPpyMilterServer.

    Args:
      port: A numeric port to listen on (TCP).
      milter_class: A class (not an instance) that handles callbacks for
                    milter commands (e.g. a child of the PpyMilter class).
      max_queued_connections: Maximum number of connections to allow to
                              queue up on socket awaiting accept().
    """
    asyncore.dispatcher.__init__(self)
    self.__milter_class = milter_class
    self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
    self.set_reuse_addr()
    self.bind(('', port))
    self.listen(max_queued_connections)

  def handle_accept(self):
    """Callback function from asyncore to handle a connection dispatching."""
    try:
      (conn, addr) = self.accept()
    except socket.error, e:
      logging.error('warning: server accept() threw an exception ("%s")',
                        str(e))
      return
    AsyncPpyMilterServer.ConnectionHandler(conn, addr, self.__milter_class)


  class ConnectionHandler(asynchat.async_chat):
    """A connection handling class that manages communication on a
    specific connection's network socket.  Receives callbacks from asynchat
    when new data appears on a socket and when an entire milter command is
    ready invokes the milter dispatching class.
    """

    # TODO: allow milter dispatcher to be overridden (PpyMilterDispatcher)?
    def __init__(self, conn, addr, milter_class):
      """A connection handling class to manage communication on this socket.

      Args:
        conn: The socket connection object.
        addr: The address (port/ip) as returned by socket.accept()
        milter_class: A class (not an instance) that handles callbacks for
                      milter commands (e.g. a child of the PpyMilter class).
      """
      asynchat.async_chat.__init__(self, conn)
      self.__conn = conn
      self.__addr = addr
      self.__milter_dispatcher = ppymilterbase.PpyMilterDispatcher(milter_class)
      self.__input = []
      self.set_terminator(MILTER_LEN_BYTES)
      self.found_terminator = self.read_packetlen

    def collect_incoming_data(self, data):
      """Callback from asynchat--simply buffer partial data in a string."""
      self.__input.append(data)

    def log_info(self, message, type='info'):
      """Provide useful logging for uncaught exceptions"""
      if type == 'info':
        logging.debug(message)
      else:
        logging.error(message)

    def read_packetlen(self):
      """Callback from asynchat once we have an integer accumulated in our
      input buffer (the milter packet length)."""
      packetlen = int(struct.unpack('!I', "".join(self.__input))[0])
      self.__input = []
      self.set_terminator(packetlen)
      self.found_terminator = self.read_milter_data

    def __send_response(self, response):
      """Send data down the milter socket.

      Args:
        response: The data to send.
      """
      logging.debug('  >>> %s', binascii.b2a_qp(response[0]))
      self.push(struct.pack('!I', len(response)))
      self.push(response)

    def read_milter_data(self):
      """Callback from asynchat once we have read the milter packet length
      worth of bytes on the socket and it is accumulated in our input buffer
      (which is the milter command + data to send to the dispatcher)."""
      inbuff = "".join(self.__input)
      self.__input = []
      logging.debug('  <<< %s', binascii.b2a_qp(inbuff))
      try:
        response = self.__milter_dispatcher.Dispatch(inbuff)
        if type(response) == list:
          for r in response:
            self.__send_response(r)
        elif response:
          self.__send_response(response)

        # rinse and repeat :)
        self.found_terminator = self.read_packetlen
        self.set_terminator(MILTER_LEN_BYTES)
      except ppymilterbase.PpyMilterCloseConnection, e:
        logging.info('Closing connection ("%s")', str(e))
        self.close()


class ThreadedPpyMilterServer(SocketServer.ThreadingTCPServer):

  def __init__(self, port, milter_class):
    SocketServer.ThreadingTCPServer.__init__(self, ('', port),
                                    ThreadedPpyMilterServer.ConnectionHandler)
    self.allow_reuse_address = True
    self.milter_class = milter_class
    self.loop = self.serve_forever


  class ConnectionHandler(SocketServer.BaseRequestHandler):
    def setup(self):
      self.request.setblocking(True)
      self.__milter_dispatcher = ppymilterbase.PpyMilterDispatcher(
          self.server.milter_class)

    def __send_response(self, response):
      """Send data down the milter socket.

      Args:
        response: the data to send
      """
      logging.debug('  >>> %s', binascii.b2a_qp(response[0]))
      self.request.send(struct.pack('!I', len(response)))
      self.request.send(response)

    def handle(self):
      try:
        while True:
          packetlen = int(struct.unpack('!I',
                                        self.request.recv(MILTER_LEN_BYTES))[0])
          data = self.request.recv(packetlen)
          logging.debug('  <<< %s', binascii.b2a_qp(data))
          try:
            response = self.__milter_dispatcher.Dispatch(data)
            if type(response) == list:
              for r in response:
                self.__send_response(r)
            elif response:
              self.__send_response(response)
          except ppymilterbase.PpyMilterCloseConnection, e:
            logging.info('Closing connection ("%s")', str(e))
            break
      except Exception:
        # use similar error production as asyncore as they already make
        # good 1 line errors - similar to handle_error in asyncore.py
        # proper cleanup happens regardless even if we catch this exception
        (nil, t, v, tbinfo) = asyncore.compact_traceback()
        logging.error('uncaptured python exception, closing channel %s '
                      '(%s:%s %s)' % (repr(self), t, v, tbinfo))


# Allow running the library directly to demonstrate a simple example invocation.
if __name__ == '__main__':
  port = 9999
  try: port = int(sys.argv[1])
  except Exception: pass

  logging.basicConfig(level=logging.DEBUG,
                      format='%(asctime)s %(levelname)s %(message)s',
                      datefmt='%Y-%m-%d@%H:%M:%S')

  server = AsyncPpyMilterServer(port, ppymilterbase.PpyMilter)
  asyncore.loop()

  #server = ThreadedPpyMilterServer(port, ppymilterbase.PpyMilter)
  #server.loop()

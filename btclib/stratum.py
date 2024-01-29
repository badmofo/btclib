'''
The MIT License (MIT)

Copyright (c) 2013 ngcccbase contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

'''
See https://electrumx.readthedocs.io/en/latest/protocol.html for methods.
'''

import socket
import json
import sys
import traceback


class ConnectionError(Exception):
    pass
    
class ElectrumError(Exception):
    pass

class ElectrumInterface(object):
    """Interface for interacting with Electrum servers using the
    stratum tcp protocol
    """

    def __init__(self, host, port, debug=False):
        """Make an interface object for connecting to electrum server
        """
        self.message_counter = 0
        self.connection = (host, port)
        self.debug = debug
        self.is_connected = False
        self.sock = None
        self.connect()
        
    def __del__(self):
        self.is_connected = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None

    def connected(self):
        return self.is_connected

    def connect(self):
        """Connects to an electrum server via TCP.
        Uses a socket so we can listen for a response
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        try:
            sock.connect(self.connection)
        except:
            msg = "Unable to connect to %s:%s!"
            raise ConnectionError(msg % self.connection)

        sock.settimeout(60)
        self.sock = sock
        self.is_connected = True
        if self.debug:
            print ("Connected to %s:%s!" % self.connection ) # pragma: no cover
        return self.get_response('server.version', ['3.2.3', '1.4'])

    def wait_for_response(self, target_id):
        """Get a response message from an electrum server with
        the id of <target_id>
        """
        try:
            out = ''
            while self.is_connected or self.connect():
                try:
                    msg = self.sock.recv(1024).decode('utf-8')
                    if self.debug:
                        print (msg)  # pragma: no cover
                except socket.timeout:         # pragma: no cover
                    self.is_connected = False  # pragma: no cover
                    continue                   # pragma: no cover
                except socket.error:                      # pragma: no cover
                    traceback.print_exc(file=sys.stdout)  # pragma: no cover
                    raise                                 # pragma: no cover

                out += msg
                if msg == '':
                    self.is_connected = False  # pragma: no cover

                # get the list of messages by splitting on newline
                raw_messages = out.split("\n")

                # the last one isn't complete
                out = raw_messages.pop()
                for raw_message in raw_messages:
                    message = json.loads(raw_message)

                    id = message.get('id')
                    error = message.get('error')
                    result = message.get('result')

                    if id == target_id:
                        if error:
                            raise ElectrumError("Received error '%s'!" % error)
                        else:
                            return result
        except KeyboardInterrupt:
            raise
        self.is_connected = False

    def get_response(self, method, params):
        """Given a message that consists of <method> which
        has <params>,
        Return the string response of the message sent to electrum"""
        current_id = self.message_counter
        self.message_counter += 1
        try:
            message = json.dumps({
                'id': current_id,
                'method': method,
                'params': params}) + "\n"
            self.sock.send(message.encode('utf-8'))
        except socket.error:                       # pragma: no cover
            traceback.print_exc(file=sys.stdout)   # pragma: no cover
            return None                            # pragma: no cover
        return self.wait_for_response(current_id)

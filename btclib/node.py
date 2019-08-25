import time
import socket
import io
import random
from btclib import *
from btclib.base import *

# TODO: implement reconnect logic?
# TODO: better exceptions (typed)

class ServiceAddress(Serializable):
    fields = [
        ('services', UnsignedInteger(64)),
        ('reserved', UnsignedInteger(96, 'big')),
        ('ip', UnsignedInteger(32, 'big')),
        ('port', UnsignedInteger(16, 'big')),
    ]

class Version(Serializable):
    fields = [
        ('version', UnsignedInteger()),
        ('services', UnsignedInteger(64)),
        ('timestamp', UnsignedInteger(64)),
        ('addr_to', ServiceAddress),
        ('addr_from', ServiceAddress),
        ('nonce', UnsignedInteger(64)),
        ('user_agent', VarBytestring),
        ('starting_height', UnsignedInteger()),
    ]

class Inv(Serializable):
    fields = [
        ('type', UnsignedInteger()),
        ('hash', LittleEndianHash256),
    ]
    
class InventoryVector(Serializable):
    fields = [
        ('inv', List(Inv)),
    ]

class Node(object):
    def __init__(self, host='localhost', port=8333, network='mainnet', debug=False):
        self.host = host
        self.port = port
        self.debug = debug
        NETWORKS = {
            'mainnet': b"\xf9\xbe\xb4\xd9",
            'testnet': b"\x0b\x11\x09\x07",
            'regtest': b"\xfa\xbf\xb5\xda",
        }
        self.network = NETWORKS[network]
        
    def connect(self):
        addr_from = ServiceAddress(1, 0xffff, 0, 0)
        addr_to = ServiceAddress(1, 0xffff, 0, 0)
        addr_to.ip = int.from_bytes(socket.inet_aton(socket.gethostbyname(self.host)), 'big')
        addr_to.port = self.port        
        MY_VERSION = 31800
        MY_USER_AGENT = b'/Node:1.0.0/' # TODO: does this have any significance?
        nonce = random.randint(0, 0xFFFFFFFFFFFFFFFF)
        version = Version(MY_VERSION, 1, int(time.time()), addr_to, addr_from, nonce, MY_USER_AGENT, 0xFFFFFFFF)
        
        self.s = socket.create_connection((self.host, self.port))
        self.send_message(b'version', version)

        while True:
            command, data = self.recv_message()
            if self.debug:
                print(command)
                print(data.hex())
            if command == b'version':
                self.send_message(b'verack')
                print(Version.deserialize_bytes(data))
            elif command == b'inv':
                self.send_message(b'getdata', data) # echo the inventory vector
            elif command == b'tx':
                self.on_transaction(data)
            elif command == b'block':
                self.on_block(data)
    
    def recv_fully(self, n):
        buffer = b''
        while True:
            bytes_read = self.s.recv(n - len(buffer))
            buffer += bytes_read
            if n >= len(buffer):
                return buffer
            if not bytes_read:
                raise Exception('short read')
    
    def recv_message(self):
        network = self.recv_fully(4)
        if network != self.network:
            raise Exception('network mismatch')
        command = self.recv_fully(12).replace(b'\00', b'')
        length = int.from_bytes(self.recv_fully(4), 'little')
        checksum = self.recv_fully(4)
        data = self.recv_fully(length)
        if checksum != dsha256(data)[:4]:
            raise Exception('checksum failure')
        return command, data
    
    def send_message(self, command, data=b''):
        buffer = io.BytesIO()
        buffer.write(self.network)
        buffer.write(command)
        buffer.write(b'\x00' * (12 - len(command)))
        if isinstance(data, Serializable):
            data = data.serialize(data)
        buffer.write(len(data).to_bytes(4, 'little'))
        buffer.write(dsha256(data)[:4])
        buffer.write(data)
        self.s.sendall(buffer.getvalue())
        
    def on_transaction(self, data):
        print(Transaction.deserialize_bytes(data))
    
    def on_block(self, data):
        print(Block.deserialize_bytes(data))

# make a redis node
class RedisNode(object):
    def __init__(self, redis, **kwargs):
        self.redis = redis
        super().__init__(**kwargs)
    
    def on_transaction(self, data):
            self.redis.publish('btc', json.dumps(('block', network, data.hex())))

    def on_block(self, data):
            self.redis.publish('btc', json.dumps(('tx', network, data.hex())))


if __name__ == '__main__':
    node = Node('localhost', 18444, 'regtest')
    node.connect()
    
import hashlib
import hmac
import re
import math
import ctypes
import ctypes.util
import base64
import os.path
from btclib.segwit_addr import segwit_decode, segwit_encode, bech32_decode, bech32_encode

def as_bytes(data):
    if isinstance(data, str):
        return data.encode('utf-8')
    else:
        return data

def sha256(data):
    return hashlib.sha256(as_bytes(data)).digest()

def dsha256(data):
    return sha256(sha256(data))

def hash160(data):
    return hashlib.new('ripemd160', sha256(data)).digest()

def hmac_sha256(key, data):
    return hmac.new(as_bytes(key), as_bytes(data), hashlib.sha256).digest()

def hmac_sha512(key, data):
    return hmac.new(as_bytes(key), as_bytes(data), hashlib.sha512).digest()

def b58encode(s):
    leading_zero_bytes = len(re.match(b'^\x00*', s).group(0))
    n = int.from_bytes(s, 'big')
    code_string = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    base = len(code_string)
    result = ''
    while n > 0:
        result = code_string[n % base] + result
        n //= base
    return '1' * leading_zero_bytes + result

def b58decode(s):
    s = as_bytes(s)
    leading_zero_bytes = len(re.match(b'^1*', s).group(0))
    code_string = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    base = len(code_string)
    result = 0
    while s:
        result *= base
        found = code_string.find(s[0])
        if found == -1:
            raise ValueError('invalid base58 character', s[0])
        result += found
        s = s[1:]
    return  b'\x00' * leading_zero_bytes + result.to_bytes(math.ceil(result.bit_length()/8), 'big')

def b58check_encode(data, version=b'\x00'):
    version_data = version + data
    checksum = dsha256(version_data)[:4]
    return b58encode(version_data + checksum)

def b58check_decode(encoded, version_length=1):
    data = b58decode(encoded)
    if dsha256(data[:-4])[:4] != data[-4:]:
        raise ValueError('data failed b58check', encoded)
    return data[:version_length], data[version_length:-4]

class Network(dict):
    def __str__(self):
        return self.name
    __repr__ = __str__

mainnet = Network({
    'p2pkh': b'\x00', 
    'p2sh':  b'\x05',
    'wif':  b'\x80',
    'xpub.p2pkh':        b'\x04\x88\xb2\x1e', # xpub
    'xpub.p2wpkh-p2sh':  b'\x04\x9d\x7c\xb2', # ypub
    'xpub.p2wsh-p2sh':   b'\x02\x95\xb4\x3f', # Ypub
    'xpub.p2wpkh':       b'\x04\xb2\x47\x46', # zpub
    'xpub.p2wsh':        b'\x02\xaa\x7e\xd3', # Zpub
    'xpriv.p2pkh':       b'\x04\x88\xad\xe4', # xprv
    'xpriv.p2wpkh-p2sh': b'\x04\x9d\x78\x78', # yprv
    'xpriv.p2wsh-p2sh':  b'\x02\x95\xb0\x05', # Yprv
    'xpriv.p2wpkh':      b'\x04\xb2\x43\x0c', # zprv
    'xpriv.p2wsh':       b'\x02\xaa\x7a\x99', # Zprv
})
mainnet.name = 'mainnet'
mainnet.hrp = 'bc'
testnet = Network({
    'p2pkh': b'\x6f',
    'p2sh':  b'\xc4',
    'wif':  b'\xef',
    'xpub.p2pkh':        b'\x04\x35\x87\xcf', # tpub
    'xpub.p2wpkh-p2sh':  b'\x04\x4a\x52\x62', # upub
    'xpub.p2wsh-p2sh':   b'\x02\x42\x89\xef', # Upub
    'xpub.p2wpkh':       b'\x04\x5f\x1c\xf6', # vpub
    'xpub.p2wsh':        b'\x02\x57\x54\x83', # Vpub
    'xpriv.p2pkh':       b'\x04\x35\x83\x94', # tprv
    'xpriv.p2wpkh-p2sh': b'\x04\x4a\x4e\x28', # uprv
    'xpriv.p2wsh-p2sh':  b'\x02\x42\x85\xb5', # Uprv
    'xpriv.p2wpkh':      b'\x04\x5f\x18\xbc', # vprv
    'xpriv.p2wsh':       b'\x02\x57\x50\x48', # Vprv
})
testnet.name = 'testnet'
testnet.hrp = 'tb'

ADDRESS_FORMATS = ('p2pkh', 'p2sh', 'p2wpkh', 'p2wsh')


def get_networks():
    return {'mainnet': mainnet, 'testnet': testnet}

def get_network(name):
    return get_networks()[name]

def grok(encoded):
    hrp, data = bech32_decode(encoded)
    if hrp is not None:
        for n in get_networks().values():
            if n.hrp == hrp:
                witver, witprog = segwit_decode(hrp, encoded)
                if witver == 0 and len(witprog) == 20:
                    return n, 'p2wpkh'
                if witver == 0 and len(witprog) == 32:
                    return n, 'p2wsh'
        return (None, '') # unsupported witness version/program
    try:
        decoded = b58decode(encoded)
        for n in [mainnet, testnet]:
            for k,v in sorted(n.items(), reverse=True):
                if decoded.startswith(v):
                    b58check_decode(encoded, version_length=len(v)) # validate checksum
                    return n, k
    except ValueError:
        pass
    return (None, '')

def addr_to_network(addr):
    network, fmt = grok(addr)
    if fmt in ADDRESS_FORMATS:
        return network.name

class InvalidKeyException(Exception): pass

class Secp256k1:
    P = 2**256-2**32-2**9-2**8-2**7-2**6-2**4-1
    N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
    Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
    G = (Gx,Gy)

# TODO: make a pure python version of this using the ecdsa library

class NativeCrypto(object):
    def __init__(self):
        # prefer path local libsecp256k1.so if it exists
        library_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'libsecp256k1.so')
        if not os.path.exists(library_path):
            library_path = ctypes.util.find_library('libsecp256k1') or ctypes.util.find_library('secp256k1')
        assert library_path, 'failed to find libsecp256k1'
        self.lib = ctypes.cdll.LoadLibrary(library_path)
        assert self.lib
        self.lib.secp256k1_context_create.restype = ctypes.c_void_p
        self.ctx = self.lib.secp256k1_context_create(0b1100000001) # sign / verify
        assert self.ctx
        self.ctx = ctypes.c_void_p(self.ctx)
    
    def ec_pubkey_parse(self, pubkey_in):
        pubkey_t_buffer = ctypes.create_string_buffer(64)
        result = self.lib.secp256k1_ec_pubkey_parse(
            self.ctx,
            ctypes.byref(pubkey_t_buffer),
            pubkey_in,
            len(pubkey_in))
        if not result:
            raise InvalidKeyException('invalid public key')
        return pubkey_t_buffer
    
    def ec_pubkey_serialize(self, pubkey_t, compressed):
        pubkey_buffer = ctypes.create_string_buffer(65)
        pubkey_length = ctypes.c_int(65)
        result = self.lib.secp256k1_ec_pubkey_serialize(
            self.ctx,
            ctypes.byref(pubkey_buffer),
            ctypes.byref(pubkey_length),
            pubkey_t,
            0b100000010 if compressed else 0b10)
        if not result:
            raise InvalidKeyException('invalid public key')
        return pubkey_buffer.raw[:pubkey_length.value]

    def ec_pubkey_decompress(self, pubkey_in):
        pubkey_t = self.ec_pubkey_parse(pubkey_in)
        return self.ec_pubkey_serialize(pubkey_t, False)
        
    def ec_pubkey_create(self, exponent, compressed=False):
        pubkey_t = ctypes.create_string_buffer(64)
        result = self.lib.secp256k1_ec_pubkey_create(
            self.ctx, 
            ctypes.byref(pubkey_t),
            exponent)
        if not result:
            raise InvalidKeyException('invalid private key')
        return self.ec_pubkey_serialize(pubkey_t, compressed)

    def ec_pubkey_tweak(self, op, pubkey, tweak, compressed=False):
        assert op in ['add', 'mul']
        f = 'secp256k1_ec_pubkey_tweak_%s' % op
        scalar = (tweak % Secp256k1.N).to_bytes(32, 'big')
        pubkey_t = self.ec_pubkey_parse(pubkey)
        result = getattr(self.lib, f)(
            self.ctx,
            ctypes.byref(pubkey_t), 
            scalar)
        if not result:
            raise Exception('error in %s' % f)
        return self.ec_pubkey_serialize(pubkey_t, compressed)
    
    def ecdsa_verify_der(self, msg32, sig_der, pubkey_in):
        pubkey = self.ec_pubkey_parse(pubkey_in)
        sig = ctypes.create_string_buffer(64)
        result = self.lib.secp256k1_ecdsa_signature_parse_der(
            self.ctx,
            ctypes.byref(sig),
            sig_der,
            len(sig_der))
        if not result:
            raise Exception('invalid signature: der')
        result = self.lib.secp256k1_ecdsa_verify(
            self.ctx,
            sig,
            msg32,
            pubkey)
        return bool(result)
    
    def ecdsa_sign_der(self, msg32, exponent):
        sig = ctypes.create_string_buffer(64)
        null_ptr = ctypes.POINTER(ctypes.c_int)()
        result = self.lib.secp256k1_ecdsa_sign(
            self.ctx, 
            ctypes.byref(sig),
            msg32,
            exponent,
            null_ptr, null_ptr) # use rfc6979 nonce
        if not result:
            raise Exception('signing error')
        # TODO: better exceptions
        sig_der = ctypes.create_string_buffer(128)
        sig_der_size = ctypes.c_int(128)
        result = self.lib.secp256k1_ecdsa_signature_serialize_der(
            self.ctx,
            ctypes.byref(sig_der),
            ctypes.byref(sig_der_size),
            sig) # byref?
        if not result:
            raise Exception('signing error: der serialization')
        return sig_der.raw[:sig_der_size.value]
        
        
    def ecdsa_sign_raw(self, msg32, exponent, compressed):
        assert len(msg32) == 32

        sig = ctypes.create_string_buffer(65)
        null_ptr = ctypes.POINTER(ctypes.c_int)()
        
        result = self.lib.secp256k1_ecdsa_sign_recoverable(
            self.ctx,
            ctypes.byref(sig),
            msg32,
            exponent,
            null_ptr, null_ptr)
        if not result:
            raise Exception('signing error: secp256k1_ecdsa_sign_recoverable')
            
        recid = ord(sig[64])
        
        sig_compact = ctypes.create_string_buffer(64)
        result = self.lib.secp256k1_ecdsa_signature_serialize_compact(self.ctx, sig_compact, sig)
        if not result:
            raise Exception('signing error: secp256k1_ecdsa_signature_serialize_compact')
    
        compressed = 4 if compressed else 0
    
        return 27 + compressed + recid, int.from_bytes(sig_compact.raw[:32], 'big'), int.from_bytes(sig_compact.raw[32:64], 'big')
            

    def ecdsa_recover(self, msg32, sig_compact, recovery_id):
        assert recovery_id in range(4)
        sig_t_buffer = ctypes.create_string_buffer(65)
        result = self.lib.secp256k1_ecdsa_recoverable_signature_parse_compact(
            self.ctx,
            ctypes.byref(sig_t_buffer),
            sig_compact,
            recovery_id)
        if not result:
            raise Exception('invalid compact signature')
        pubkey_t = ctypes.create_string_buffer(64)
        result = self.lib.secp256k1_ecdsa_recover(
            self.ctx,
            ctypes.byref(pubkey_t),
            ctypes.byref(sig_t_buffer),
            msg32)
        if not result:
            raise Exception('invalid signature')
        return self.ec_pubkey_serialize(pubkey_t, False)

crypto = NativeCrypto()

class PrivateKey(object):
    def __init__(self, key, compressed=False, network=None):
        self.network = network or mainnet # TODO: put network in scope of something?
        self.compressed = compressed
        self.secret = None
        if isinstance(key, int):
            if key <= 0 or key > Secp256k1.N:
                raise InvalidKeyException('private key out of range')
            key = key.to_bytes(32, 'big')
        if len(key) == 64 and isinstance(key, str):
            key = bytes.fromhex(key)
        elif len(key) != 32 and isinstance(key, str):
            self.network, fmt = grok(key)
            if fmt != 'wif':
                raise InvalidKeyException('invalid private key')
            version, key = b58check_decode(key)
            # TODO: impl https://github.com/bitcoin/bips/blob/master/bip-0178.mediawiki
            if len(key) == 33 and key[-1] == 1:
                self.compressed = True
                key = key[:32]
        if len(key) == 32 and isinstance(key, bytes):
            self.secret = int.from_bytes(key, 'big')
            if self.secret > Secp256k1.N:
                raise InvalidKeyException('private key out of range')
        if not self.secret or not self.network:
            raise InvalidKeyException('invalid private key')
        self.key = key
        self._pub = None

    def encode(self, key_format='bin', compressed=None, network=None):
        key_bin = self.secret.to_bytes(32, 'big')
        compressed = self.compressed if compressed is None else compressed
        if key_format == 'bin':
            return key_bin
        elif key_format == 'hex':
            return key_bin.hex()
        elif key_format == 'decimal':
            return self.secret
        elif key_format == 'wif':
            network = self.network if network is None else network
            return b58check_encode(key_bin + (b'\x01' if compressed else b''), network['wif'])
        else:
            raise ValueError('unrecognized format')
    
    def pub(self):
        if self._pub != None and self._pub.compressed == self.compressed:
            return self._pub
        self._pub = PublicKey(crypto.ec_pubkey_create(self.key, False), self.compressed, self.network)
        return self._pub

    def ecdsa_raw_sign(self, msghash):
        return crypto.ecdsa_sign_der(msghash, self.key)
        
    def message_sign(self, message):
        message_hash = message_sig_hash(message)
        v,r,s = crypto.ecdsa_sign_raw(message_hash, self.encode('bin'), self.compressed)
        return base64.b64encode(v.to_bytes(1, 'big') + r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))
    
    def __add__(self, tweak):
        assert isinstance(tweak, int)
        s = (self.secret + tweak) % Secp256k1.N
        return PrivateKey(s.to_bytes(32, 'big'), self.compressed, self.network)
        
    def __mul__(self, tweak):
        assert isinstance(tweak, int)
        s = (self.secret * tweak) % Secp256k1.N
        return PrivateKey(s.to_bytes(32, 'big'), self.compressed, self.network)

class PublicKey(object):
    def __init__(self, pubkey_sec, compressed=None, network=None):
        self.network = network or mainnet
        if isinstance(pubkey_sec, str):
            if len(pubkey_sec) in (130, 66):
                pubkey_sec = bytes.fromhex(pubkey_sec)
            else:
                raise InvalidKeyException('invalid public key')
        self.key = crypto.ec_pubkey_decompress(pubkey_sec) # always store decompressed
        self.compressed = compressed if compressed is not None else len(pubkey_sec) == 33
    
    def point(self):
        x = int.from_bytes(self.key[1:33], 'big')
        y = int.from_bytes(self.key[33:65], 'big')
        return (x, y)
    
    def encode(self, key_format, compressed=None, network=None):
        # TODO: clean this shit up
        key_bin = self.key
        compressed = self.compressed if compressed is None else compressed
        if key_format in ('p2wpkh', 'p2wsh'):
            compressed = True
        
        if compressed and len(self.key) == 65:
            x, y = self.point()
            key_bin = bytes([2 + (y % 2)]) + x.to_bytes(32, 'big')
        
        if key_format == 'bin':
            return key_bin
        elif key_format == 'hex':
            return key_bin.hex()
        elif key_format == 'pkh':
            return hash160(key_bin)
        elif key_format in ('p2pkh', 'p2wpkh', 'p2wsh'):
            return pubkey_to_addr(key_bin, self.network if network is None else network, key_format)
        else:
            raise ValueError('unrecognized format')
        
    def __add__(self, tweak):
        return PublicKey(crypto.ec_pubkey_tweak('add', self.key, tweak), self.compressed, self.network)
        
    def __mul__(self, tweak):
        return PublicKey(crypto.ec_pubkey_tweak('mul', self.key, tweak), self.compressed, self.network)
    
    def ecdsa_raw_verify(self, msghash, sig_der):
        return crypto.ecdsa_verify_der(msghash, sig_der, self.encode('bin'))
    

def message_sig_hash(message):
    from btclib.base import CompactSize
    padded = b'\x18Bitcoin Signed Message:\n' + CompactSize.serialize(len(message)) + message.encode('utf8')
    return dsha256(padded)


def message_verify(message, signature):
    message_hash = message_sig_hash(message)
    signature = base64.b64decode(signature)
    if len(signature) != 65:
        return False
    v, r, s = signature[0], int.from_bytes(signature[1:33], 'big'), int.from_bytes(signature[33:], 'big')
    sig_compact = signature[1:]
    
    if v < 27 or v >= 35:
        #raise Exception("Bad encoding")
        return False
    if v >= 31:
        compressed = True
        v -= 4
    else:
        compressed = False
    recovery_id = v - 27
    try:
        pubkey_sec = crypto.ecdsa_recover(message_hash, sig_compact, recovery_id)
        return PublicKey(pubkey_sec, compressed=compressed)
    except Exception:
        pass


def bip32_deserialize(data):
    vbyte, data = b58check_decode(data, 4)
    depth = data[0]
    fingerprint = data[1:5]
    i = int.from_bytes(data[5:9], 'big')
    chaincode = data[9:41]
    keydata = data[41:]
    return vbyte, depth, fingerprint, i, chaincode, keydata
    
def bip32_serialize(vbyte, depth, fingerprint, i, chaincode, keydata):
    data = vbyte + bytes([depth % 256]) + fingerprint + i.to_bytes(4, 'big') + chaincode + keydata
    return b58check_encode(data[1:], data[:1])

class HDKey(object):
    def __init__(self, depth, fingerprint, i, chaincode, key, address_format='p2pkh'):
        self.depth = depth
        self.fingerprint = fingerprint
        self.i = i
        self.chaincode = chaincode
        self.key = key
        self.network = key.network
        self.address_format = address_format
    
    def derive_path(self, path):
        result = self
        for n in path:
            result = result.derive(n)
        return result


class HDPrivateKey(HDKey):
    @classmethod
    def from_seed(cls, seed, network=mainnet, address_format='p2pkh'):
        I = hmac_sha512(b'Bitcoin seed', seed)
        return cls(0, b'\x00' * 4, 0, I[32:], PrivateKey(I[:32], True, network), address_format)
    
    @classmethod
    def from_xpriv(cls, xpriv):
        vbyte, depth, fingerprint, i, chaincode, keydata = bip32_deserialize(xpriv)
        network, fmt = grok(xpriv)
        if not fmt.startswith('xpriv'):
            raise ValueError('invalid xpriv')
        address_format = fmt[6:]
        key = PrivateKey(keydata[1:], True, network)
        return cls(depth, fingerprint, i, chaincode, key, address_format)
    
    def xpub(self):
        if not hasattr(self, '_xpub'):
            self._xpub = HDPublicKey(self.depth, self.fingerprint, self.i, self.chaincode, self.pub(), self.address_format)
        return self._xpub
    
    def priv(self):
        return self.key
    
    def pub(self):
        return self.key.pub()
        
    def encode(self, network=None):
        network = network if network else self.network
        return bip32_serialize(network['xpriv.%s' % (self.address_format,)], self.depth, self.fingerprint, self.i, self.chaincode, bytes([0]) + self.key.encode('bin'))
    
    def derive(self, n):
        if isinstance(n, int):
            if n > 2**32 or n < 0:
                raise ValueError('index bip32 invalid')
            fingerprint = hash160(self.pub().encode('bin'))[:4]
            hardened = n >= 2**31
            s = n.to_bytes(4, 'big')
            depth = self.depth + 1
        elif isinstance(n, bytes): # non-standard; used by electrum for 2fa
            fingerprint = b'\x00' * 4
            hardened = False
            s = n
            n = depth = 0
        if hardened:
            data = b'\x00' + self.priv().encode('bin') + s
        else:
            data = self.pub().encode('bin', compressed=True) + s
        I = hmac_sha512(self.chaincode, data)
        c = I[32:]
        k = self.priv() + int.from_bytes(I[:32], 'big')
        return HDPrivateKey(depth, fingerprint, n, c, k, self.address_format)

class HDPublicKey(HDKey):
    @classmethod
    def from_xpub(cls, xpub):
        vbyte, depth, fingerprint, i, chaincode, keydata = bip32_deserialize(xpub)
        network, fmt = grok(xpub)
        if (not fmt.startswith('xpub')) or len(keydata) != 33:
            raise ValueError('invalid xpub')
        address_format = fmt[5:]
        key = PublicKey(keydata, True, network)
        return cls(depth, fingerprint, i, chaincode, key, address_format)
    
    def pub(self):
        return self.key

    def encode(self, network=None):
        network = network if network else self.network
        return bip32_serialize(network['xpub.%s' % (self.address_format,)], self.depth, self.fingerprint, self.i, self.chaincode, self.key.encode('bin'))
    
    def encode_compact(self, path):
        assert len(path) == 2
        xpub = self.encode()
        return b'\xff' + b58decode(xpub.encode())[:-4] + path[0].to_bytes(2, 'little') + path[1].to_bytes(2, 'little')
    
    def derive(self, n):
        assert isinstance(n, (int, bytes)), type(n)
        if isinstance(n, int):
            fingerprint = hash160(self.pub().encode('bin'))[:4]
            if n >= 2**31 or n < 0:
                raise ValueError('index bip32 invalid')
            s = n.to_bytes(4, 'big')
            depth = self.depth + 1
        elif isinstance(n, bytes): # non-standard; used by electrum for 2fa
            fingerprint = b'\x00' * 4
            s = n
            n = depth = 0
        I = hmac_sha512(self.chaincode, self.key.encode('bin') + s)
        K = self.key + int.from_bytes(I[:32], 'big')
        c = I[32:]
        return HDPublicKey(depth, fingerprint, n, c, K, self.address_format)

def derive_electrum(master_pubkey, n, for_change=0):
    mpk = master_pubkey.encode('bin', compressed=False)[1:]
    tweak = dsha256((b'%d:%d:' % (n, for_change)) + mpk)
    return master_pubkey + int.from_bytes(tweak, 'big')

# See: http://docs.electrum.org/en/latest/transactions.html
def derive_compact_xpub(compact_xpub):
    ''' Return (xpub, path, pub) as (HDPublicKey, list, PublicKey)'''
    if compact_xpub[0] == 0xff: # bip32 xpub
        data = compact_xpub[1:79]
        path = compact_xpub[79:]
        if len(path) != 4:
            return None
        path = [int.from_bytes(path[0:2], 'little'), int.from_bytes(path[2:4], 'little')]
        xpub = HDPublicKey.from_xpub(b58check_encode(data[1:], data[:1]))
        derived = xpub.derive_path(path).pub()
        return xpub, path, derived
    elif compact_xpub[0] == 0xfe: # electrum 1.x xpub
        master_public_key_hex = b'04' + compact_xpub[1:129]
        master_public_key = PublicKey(bytes.fromhex(master_public_key_hex.decode('utf-8')))
        path = compact_xpub[129:]
        if len(path) != 4:
            return None
        for_change, n = [int.from_bytes(path[0:2], 'little'), int.from_bytes(path[2:4], 'little')]
        pub = derive_electrum(master_public_key, n, for_change)
        return master_public_key, (for_change, n), pub
    else:
        return None, None, PublicKey(compact_xpub)


# TODO: clean this up
from btclib.base import *
from btclib.script import *


def pubkey_to_addr(pubkey_sec, network=mainnet, address_type='p2pkh'):
    if isinstance(pubkey_sec, str):
        pubkey_sec = bytes.fromhex(pubkey_sec)
    if address_type == 'p2pkh':
        return b58check_encode(hash160(pubkey_sec), network['p2pkh'])
    elif address_type == 'p2wpkh':
        return segwit_encode(network.hrp, 0, hash160(pubkey_sec))
    elif address_type == 'p2wsh':
        wsh = sha256(compile_script([pubkey_sec, Script.OP_CHECKSIG]))
        return segwit_encode(network.hrp, 0, wsh)
    raise ValueError('unsupported address_type: %s' % (address_type,))

import io
import json
import copy

from btclib import sha256, dsha256, grok, b58check_decode, PublicKey, derive_compact_xpub
from btclib.segwit_addr import bech32_decode, segwit_decode

class SerializationError(Exception):
    """ Thrown when there's a problem deserializing or serializing """
    pass
    
def read_fully(f, n):
    data = f.read(n)
    if not data or len(data) != n:
        raise SerializationError('short read')
    return data

class Serializable(object):
    fields = tuple()
    
    def __init__(self, *args):
        for (field, _), arg in zip(self.fields, args):
            setattr(self, field, arg)
    
    @classmethod
    def serialize(cls, obj):
        return b''.join(
            sedes.serialize(getattr(obj, field))
            for field, sedes in cls.fields)
    
    @classmethod
    def deserialize(cls, f):
        args = [sedes.deserialize(f) for field, sedes in cls.fields]
        return cls(*args)
        
    @classmethod
    def deserialize_bytes(cls, b):
        return cls.deserialize(io.BytesIO(b))
        
    @classmethod
    def deserialize_hex(cls, s):
        return cls.deserialize_bytes(bytes.fromhex(s))
        
    def json(self):
        d = {}
        for f,t in self.fields:
            v = getattr(self, f)
            if isinstance(v, Serializable):
                v = v.json()
            elif isinstance(v, list):
                v = [i.json() for i in v]
            elif isinstance(v, bytes):
                v = v.hex()
            d[f] = v
        return d
        
    def __repr__(self):
        return json.dumps(self.json(), indent=1)

def serialize(obj):
    return obj.serialize(obj)

class CompactSize(Serializable):
    @classmethod
    def serialize(cls, size):
        if not (0 <= size < (1<<64)):
            raise SerializationError('value too big')
        if size < 253:
            return bytes([size])
        elif size < (1<<16):
            return b'\xfd' + size.to_bytes(2, 'little')
        elif size < (1<<32):
            return b'\xfe' + size.to_bytes(4, 'little')
        elif size < (1<<64):
            return b'\xff' + size.to_bytes(8, 'little')
    
    @classmethod
    def deserialize(cls, f):
        size = int.from_bytes(read_fully(f, 1), 'little')
        bytes = 1 << max(size - 252, 0)
        if bytes > 1:
            size = int.from_bytes(f.read(bytes), 'little')
        return size

def List(ser):
    class ListClass(Serializable):
        @classmethod
        def serialize(cls, obj):
            return CompactSize.serialize(len(obj)) + b''.join(ser.serialize(o) for o in obj)

        @classmethod
        def deserialize(cls, f):
            size = CompactSize.deserialize(f)
            return [ser.deserialize(f) for i in range(size)]
    
    return ListClass

def UnsignedInteger(bits=32, endian='little'):
    class UnsignedIntegerClass(Serializable):
        @classmethod
        def serialize(cls, obj):
            return int(obj).to_bytes(bits//8, endian)
        
        @classmethod
        def deserialize(cls, f):
            return int.from_bytes(read_fully(f, bits//8), endian)
    
    return UnsignedIntegerClass

class LittleEndianHash256(Serializable):
    @classmethod
    def serialize(cls, obj):
        return obj[::-1]
        
    @classmethod
    def deserialize(cls, f):
        return read_fully(f, 32)[::-1]

class VarBytestring(Serializable):
    MAX_SIZE = 0xFFFFFFFF
    
    @classmethod
    def serialize(cls, obj):
        if len(obj) > cls.MAX_SIZE: 
            raise SerializationError('size too big')
        return CompactSize.serialize(len(obj)) + obj
        
    @classmethod
    def deserialize(cls, f):
        size = CompactSize.deserialize(f)
        if size == 0:
            return b''
        elif size > cls.MAX_SIZE: 
            raise SerializationError('size too big')
        return read_fully(f, size)

class Script(VarBytestring):
    MAX_SIZE = 10000

class TxInput(Serializable):
    fields = [
        ('txid', LittleEndianHash256),
        ('n', UnsignedInteger()),
        ('script', Script),
        ('sequence', UnsignedInteger())]

class TxOutput(Serializable):
    fields = [
        ('value', UnsignedInteger(64)),
        ('script', Script)]

from btclib.script import compile_script, parse_multisig_p2sh_script_sig  # TODO: straighten out deps

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

NO_SIGNATURE = b'\xff' # used a placeholder for missing signature by electrum
COINBASE_TXID = b'\x00' * 32 

# TODO: fix this shit
from btclib.script import create_redeem_script, parse_script, int_to_opcode, script_pubkey_to_pubkey_hash

class Transaction(Serializable):
    fields = [
        ('version', UnsignedInteger()),
        ('inputs', List(TxInput)),
        ('outputs', List(TxOutput)),
        ('lock_time', UnsignedInteger())]
    
    def hex(self):
        return Transaction.serialize(self).hex()
    
    def hash(self):
        return txhash(serialize(self))
    
    def is_coinbase(self):
        return (len(self.inputs) == 1 
            and self.inputs[0].n == 0xFFFFFFFF
            and self.inputs[0].txid == COINBASE_TXID)

    def signature_form(self, i, script_pubkey, sighash=SIGHASH_ALL):
        tx = copy.deepcopy(self)
        for input in tx.inputs:
            input.script = b''
        tx.inputs[i].script = script_pubkey
        if (sighash & 0x1f) == SIGHASH_NONE:
            tx.outputs = []
            for j,input in enumerate(tx.inputs):
                if j != i:
                    input.sequence = 0
        if (sighash & 0x1f) == SIGHASH_SINGLE:
            tx.outputs = tx.outputs[:i+1]
            for output in tx.outputs[:i]:
                output.script = b''
                output.value = 0xffffffffffffffff
            for j,input in enumerate(tx.inputs):
                if j != i:
                    input.sequence = 0
        if (sighash & SIGHASH_ANYONECANPAY):
            tx.inputs = [tx.inputs[i]]
        return self.serialize(tx) + (sighash).to_bytes(4, 'little')

    def signature_hash(self, i, script_pubkey, sighash=SIGHASH_ALL):
        one = (1).to_bytes(32, 'little')
        if i >= len(self.inputs):
            return one
        if (sighash & 0x1f) == SIGHASH_SINGLE and i >= len(self.outputs):
            return one
        return dsha256(self.signature_form(i, script_pubkey, sighash))
        
    def verify_input(self, i, script_pubkey, sig, pub):
        # TODO: in certain cases you can deduce the sig/pub from the input script_sig
        sig_der, sighash = sig[:-1], sig[-1]
        txhash = self.signature_hash(i, script_pubkey, sighash)
        pubkey = PublicKey(pub)
        return pubkey.ecdsa_raw_verify(txhash, sig_der)

    def generate_signature(self, i, script_pubkey, priv, sighash=SIGHASH_ALL):
        txhash = self.signature_hash(i, script_pubkey, sighash)
        return priv.ecdsa_raw_sign(txhash) + sighash.to_bytes(1, 'little')

    def sign_input(self, i, script_pubkey, priv, sighash=SIGHASH_ALL):
        sig = self.generate_signature(i, script_pubkey, priv, sighash)
        self.inputs[i].script = compile_script([sig, priv.pub().encode('bin')])

    def sign(self, priv, sighash=SIGHASH_ALL):
        addr = priv.pub().encode('p2pkh')
        script_pubkey = addr_to_script(addr)
        for i in range(len(self.inputs)):
            self.sign_input(i, script_pubkey, priv, sighash)
    
    def multisign_input(self, i, priv, sighash=SIGHASH_ALL):
        script_sig = parse_multisig_p2sh_script_sig(self.inputs[i].script)
        if not script_sig:
            return
        threshold, pubkeys, sigs, redeem_script = script_sig
        pubkey_sig_map = {}
        for sig in sigs:
            for pubkey in pubkeys:
                if self.verify_input(i, redeem_script, sig, pubkey):
                    pubkey_sig_map[pubkey] = sig
                    break
        if len(pubkey_sig_map) < threshold:
            pubkey = priv.pub().encode('bin')
            if pubkey in pubkeys and pubkey not in pubkey_sig_map:
                pubkey_sig_map[pubkey] = self.generate_signature(i, redeem_script, priv, sighash)
        combined_sigs = [pubkey_sig_map[p] for p in pubkeys if p in pubkey_sig_map]
        combined_sigs = combined_sigs[:threshold]
        script = [Script.OP_0] + combined_sigs + [redeem_script]
        self.inputs[i].script = compile_script(script)
        return len(combined_sigs) == threshold

    def multisign_compact_input(self, i, xpriv, sighash=SIGHASH_ALL):
        # TODO: make sure this doesn't freak on xpubs in redeem_Script
        script_sig = parse_multisig_p2sh_script_sig(self.inputs[i].script)
        if not script_sig:
            return
        threshold, pubkeys, sigs, redeem_script = script_sig
        if NO_SIGNATURE not in sigs: # nothing to sign
            return
    
        signing_xpub = xpriv.xpub()
        compact_xpubs = list(map(derive_compact_xpub, pubkeys))
        
        pubkeys = [pub for xpub, path, pub in compact_xpubs]
        final_redeem_script = create_redeem_script(threshold, pubkeys)
    
        for j, (xpub, path, pub) in enumerate(compact_xpubs):
            # TODO: better equality check for xpub
            # TODO: xpub might be None!!!
            if sigs[j] == NO_SIGNATURE and signing_xpub.encode() == xpub.encode():
                priv = xpriv.derive_path(path).priv()
                sigs[j] = self.generate_signature(i, final_redeem_script, priv, sighash)
    
        complete = False
        num_sigs = len(sigs) - sigs.count(NO_SIGNATURE)
        if num_sigs >= threshold: # if complete rewrite in non-compact form
            complete = True
            sigs = [s for s in sigs if s != NO_SIGNATURE]
            redeem_script = final_redeem_script
        script_sig = [Script.OP_0] + sigs + [redeem_script]
        self.inputs[i].script = compile_script(script_sig)
        
        return complete


class BlockHeader(Serializable):
    fields = [
        ('version', UnsignedInteger()),
        ('previous', LittleEndianHash256),
        ('merkle_root', LittleEndianHash256),
        ('time', UnsignedInteger()),
        ('bits', UnsignedInteger()),
        ('nonce', UnsignedInteger())]

class Block(Serializable):
    fields = [
        ('header', BlockHeader),
        ('txs', List(Transaction))]

def addr_to_script(addr):
    network, addr_type = grok(addr)
    if addr_type in ('p2pkh', 'p2sh'):
        _, data = b58check_decode(addr)
        if addr_type == 'p2pkh':
            return compile_script([Script.OP_DUP, Script.OP_HASH160, data, Script.OP_EQUALVERIFY, Script.OP_CHECKSIG])
        elif addr_type == 'p2sh':
            return compile_script([Script.OP_HASH160, data, Script.OP_EQUAL])
    elif addr_type in ('p2wpkh', 'p2wsh'):
        hrp, data = bech32_decode(addr)
        witver, witprog = segwit_decode(hrp, addr)
        return compile_script([int_to_opcode(witver), bytes(witprog)])
    raise Exception('unsupported addr type')


def addr_to_pubkey_hash(addr):
    return script_pubkey_to_pubkey_hash(addr_to_script(addr))

    
def electrum_script_hash(addr):
    '''Script hash format used by Electrum servers.'''
    return sha256(addr_to_script(addr))[::-1].hex()

def txhash(tx):
    if isinstance(tx, bytes):
        return dsha256(tx)[::-1].hex()
    if isinstance(tx, str):
        return txhash(bytes.fromhex(tx))
    raise ValueError('tx must be as bytes or hex string')

def mktx(inputs, outputs):
    ins = [TxInput(bytes.fromhex(i['txid']), i['n'], b'', 0xffffffff) for i in inputs]
    outs = [TxOutput(value, addr_to_script(addr)) for addr,value in outputs.items()]
    return Transaction(1, ins, outs, 0)

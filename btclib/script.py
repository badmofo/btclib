import io
from btclib import hash160, b58check_encode, mainnet
from btclib.base import SerializationError, Script, read_fully
from btclib.segwit_addr import segwit_encode

opcode_names = '''
    PUSHDATA1 PUSHDATA2 PUSHDATA4 1NEGATE RESERVED 1 2 3 4 5 6 7 8 9 10 11 12
    13 14 15 16 NOP VER IF NOTIF VERIF VERNOTIF ELSE ENDIF VERIFY RETURN
    TOALTSTACK FROMALTSTACK 2DROP 2DUP 3DUP 2OVER 2ROT 2SWAP IFDUP DEPTH DROP
    DUP NIP OVER PICK ROLL ROT SWAP TUCK CAT SUBSTR LEFT RIGHT SIZE INVERT AND
    OR XOR EQUAL EQUALVERIFY RESERVED1 RESERVED2 1ADD 1SUB 2MUL 2DIV NEGATE
    ABS NOT 0NOTEQUAL ADD SUB MUL DIV MOD LSHIFT RSHIFT BOOLAND BOOLOR
    NUMEQUAL NUMEQUALVERIFY NUMNOTEQUAL LESSTHAN GREATERTHAN LESSTHANOREQUAL
    GREATERTHANOREQUAL MIN MAX WITHIN RIPEMD160 SHA1 SHA256 HASH160 HASH256
    CODESEPARATOR CHECKSIG CHECKSIGVERIFY CHECKMULTISIG CHECKMULTISIGVERIFY
    NOP1 CHECKLOCKTIMEVERIFY CHECKSEQUENCEVERIFY NOP4 NOP5 NOP6 NOP7 NOP8 NOP9 NOP10'''
opcode_map = {0x00: 'OP_0'}
for name, code in zip(opcode_names.split(), range(76, 186)):
    opcode_map[code] = 'OP_' + name
for code, name in opcode_map.items():
    setattr(Script, name, code)
    
def opcode_to_int(op):
    codes = [0, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96]
    return codes.index(op) if op in codes else None

def int_to_opcode(n):
    return [0, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96][n]

def parse_script(script_bytes, readable=False):
    f = io.BytesIO(script_bytes)
    parsed = []
    while True:
        b = f.read(1)
        if not b:
            break
        op = int.from_bytes(b, 'little')
        if 0 < op < 76:
            parsed.append(read_fully(f, op))
        elif op in opcode_map:
            if op in [Script.OP_PUSHDATA1, Script.OP_PUSHDATA2, Script.OP_PUSHDATA4]:
                size_bytes = 1 << (op - Script.OP_PUSHDATA1)
                n = int.from_bytes(read_fully(f, size_bytes), 'little')
                parsed.append(read_fully(f, n))
            else:
                parsed.append(opcode_map[op] if readable else op)
        else:
            raise SerializationError('invalid opcode')
    return parsed

def compile_script(ops):
    compiled = bytearray()
    for o in ops:
        if o in opcode_map:
            compiled.append(o)
        elif isinstance(o, bytes):
            n = len(o)
            if n < 76:
                compiled.append(n)
                compiled.extend(o)
            elif n < 0xff:
                compiled.append(Script.OP_PUSHDATA1)
                compiled.append(n)
                compiled.extend(o)
            elif n < 0xffff:
                compiled.append(Script.OP_PUSHDATA2)
                compiled.extend(n.to_bytes(2, 'little'))
                compiled.extend(o)
            elif n < 0xffffffff:
                compiled.append(Script.OP_PUSHDATA4)
                compiled.extend(n.to_bytes(4, 'little'))
                compiled.extend(o)
            else:
                raise SerializationError('invalid data push')
        elif isinstance(o, str) and hasattr(Script, o) and o.startswith('OP_'):
            compiled.append(getattr(Script, o))
        else:
            raise SerializationError('invalid script op')
    return bytes(compiled)

def script_pubkey_to_pubkey_hash(spk):
    # TODO: this does not find non-standard pushes
    if len(spk) == 25 and spk[:3] == b'\x76\xa9\x14' and spk[-2:] == b'\x88\xac':
        return spk[3:-2] # pkh
    elif len(spk) in (67, 35) and spk[-1:] == b'\xac':
        return hash160(spk[1:-1]) # pk
    elif spk[0:2] == b'\x00\x14' and len(spk) == 22: # p2wpkh
        return spk[2:]

def script_pubkey_to_script_hash(spk):
    # TODO: this does not find non-standard pushes
    if len(spk) == 23 and spk[:2] == b'\xa9\x14' and spk[-1:] == b'\x87': # p2sh
        return spk[2:-1]
    elif spk[0:2] == b'\x00\x20' and len(spk) == 34: # p2wsh
        return spk[2:]

def script_to_addr(script, network=mainnet):
    # TODO: this does not find non-standard pushes
    # TODO: support witver != 0
    spk = script
    if len(spk) == 25 and spk[:3] == b'\x76\xa9\x14' and spk[-2:] == b'\x88\xac':
        return b58check_encode(spk[3:-2], network['p2pkh'])
    elif len(spk) in (67, 35) and spk[-1:] == b'\xac': # p2pk
        return b58check_encode(hash160(spk[1:-1]), network['p2pkh'])
    elif len(spk) == 23 and spk[:2] == b'\xa9\x14' and spk[-1:] == b'\x87':
        return b58check_encode(spk[2:-1], network['p2sh'])
    elif spk[0:2] == b'\x00\x14' and len(spk) == 22:
        return segwit_encode(network.hrp, 0, spk[2:])
    elif spk[0:2] == b'\x00\x20' and len(spk) == 34:
        return segwit_encode(network.hrp, 0, spk[2:])
    

def p2sh_addr(script, network=mainnet):
    return b58check_encode(hash160(script), network['p2sh'])

def guess_script_pubkey(script_sig):
    ops = parse_script(script_sig)
    sig, pubkey = get_sig_pubkey(ops)
    if sig and pubkey:
        return compile_script([
            Script.OP_DUP, Script.OP_HASH160, 
            hash160(pubkey), 
            Script.OP_EQUALVERIFY, Script.OP_CHECKSIG])
    if len(ops) >= 3 and ops[0] == Script.OP_0 and isinstance(ops[-1], bytes):
        return ops[-1]

def is_all_pushes(ops):
    for op in ops:
        if not isinstance(op, bytes):
            return False
    return True

def get_sig_pubkey(ops):
    if len(ops) == 2 and is_all_pushes(ops):
        sig, pubkey = ops
        if len(sig) > 60 and len(pubkey) in (33, 65):
            return sig, pubkey
    return None, None

def der_decode_sig(sig):
    leftlen = int.from_bytes(sig[3:4], 'big')
    left = sig[4:4+leftlen]
    rightlen = int.from_bytes(sig[5+leftlen:6+leftlen], 'big')
    right = sig[6+leftlen:6+leftlen+rightlen]
    return (int.from_bytes(left, 'big'), int.from_bytes(right, 'big'))

def get_multisig_pubkeys(script_bytes):
    script = parse_script(script_bytes)
    if len(script) not in range(4, 21):
        return 0, []
    if script[-1] != Script.OP_CHECKMULTISIG:
        return 0, []
    threshold = opcode_to_int(script[0])
    num_pubkeys = opcode_to_int(script[-2])
    pubkeys = script[1:-2] # TODO: returning raw bytes as pubkeys
    if not (threshold or num_pubkeys) or num_pubkeys != len(pubkeys):
        return 0, []
    # TODO: optionally sanity check the public keys ... although allow electrum style xpubs
    # InvalidKeyException
    return threshold, pubkeys

def parse_multisig_p2sh_script_sig(script):
    script = parse_script(script)
    if len(script) < 2:
        return
    if script[0] != Script.OP_0:
        return
    redeem_script = script[-1]
    if not isinstance(redeem_script, bytes):
        return
    threshold, pubkeys = get_multisig_pubkeys(redeem_script)
    if not (threshold or pubkeys):
        return
    sigs = [sig for sig in script[1:-1] if sig]
    return threshold, pubkeys, sigs, redeem_script


# TODO: come up with a better name for this
def create_redeem_script(threshold, pubs):
    script = [int_to_opcode(threshold)] + [p.encode('bin') for p in pubs] + [int_to_opcode(len(pubs)), Script.OP_CHECKMULTISIG]
    return compile_script(script)
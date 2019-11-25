import os
from btclib import *
from contextlib import AbstractContextManager


class ExceptionExpected(Exception): pass

class assert_exception(AbstractContextManager):
    def __init__(self, *exceptions):
        self._exceptions = exceptions
    def __enter__(self):
        pass
    def __exit__(self, exctype, excinst, exctb):
        if exctype is None:
            raise ExceptionExpected(self._exceptions)
        elif issubclass(exctype, self._exceptions):
            return True
        else:
            return False

if __name__ == '__main__':

    import sys
    import bitcoin
    import requests
    from btclib.base import *
    from btclib.node import *
    from btclib.script import *
    from btclib.jsonrpc import JsonRpcProxy, JsonRpcException
    from btclib.chain import BitcoindChain
    from btclib.stratum import ElectrumInterface, ConnectionError
    
    message = 'this is the way the world ends'
    priv = PrivateKey(sha256('correct horse battery staple'))
    signature = priv.message_sign(message)
    assert signature == b'G46dsSXLsM/jjqwvOtMrg3JeqKpFbvNnq7k1tkGSuxr3DACkZlYpIPmEqq9BeI1FLuo66PnqnZHvzaVFSzmoeTw='
    signer = message_verify(message, signature)
    assert signer.encode('hex') == priv.pub().encode('hex')
    
    priv = PrivateKey(sha256('correct horse battery staple'), compressed=True, network=testnet)
    signature = priv.message_sign(message)
    signer = message_verify(message, signature)
    assert signer.encode('hex') == priv.pub().encode('hex')
    
    with assert_exception(InvalidKeyException):
        pubkey_sec = priv.pub().encode('bin')
        PublicKey(pubkey_sec[:-1])
        
    with assert_exception(InvalidKeyException):
        PrivateKey(b'\x00' * 32)
    
    with assert_exception(InvalidKeyException):
        PrivateKey(b'\xff' * 32)

    with assert_exception(InvalidKeyException):
        PrivateKey(0)
        
    x = 88985120633792790105905686761572077713049967498756747774697023364147812997770
    priv = PrivateKey(x)
    assert priv.encode('decimal') == x
    pub = priv.pub()
    pub.compressed = True
    assert pub.encode('bin').hex() == '0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71'
    assert pub.encode('hex') == '0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71'
    assert pub.encode('pkh').hex() == '79fbfc3f34e7745860d76137da68f362380c606c'
    assert pub.encode('p2pkh') == '1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8'
    assert pub.encode('p2wpkh') == 'bc1q08alc0e5ua69scxhvyma568nvguqccrv4cc9n4'
    assert pub.encode('p2wsh') == 'bc1qgatzazqjupdalx4v28pxjlys2s3yja9gr3xuca3ugcqpery6c3squ55wct'
    with assert_exception(ValueError):
        pub.encode('fubar')
    key1 = '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
    key2 = '0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71'
    assert PublicKey(key1).encode('hex') == key1
    assert PublicKey(key2).encode('hex') == key2
    with assert_exception(ValueError):
        PublicKey(key2).encode('so not a public key')
    
    addresses = [
        '1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8',
        '3F3aZJZDuhixB4GfTgc1b9KFXjcaDAPF53',
        'bc1q08alc0e5ua69scxhvyma568nvguqccrv4cc9n4',
        'bc1qgatzazqjupdalx4v28pxjlys2s3yja9gr3xuca3ugcqpery6c3squ55wct',
    ]
    
    for addr in addresses:
        assert script_to_addr(addr_to_script(addr)) == addr, addr
    
    with assert_exception(Exception):
        addr_to_script('not an addr')

    assert addr_to_pubkey_hash('1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8').hex() == '79fbfc3f34e7745860d76137da68f362380c606c'        
    assert script_pubkey_to_pubkey_hash(addr_to_script('1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8')).hex() == '79fbfc3f34e7745860d76137da68f362380c606c'
    assert script_pubkey_to_pubkey_hash(addr_to_script('bc1q08alc0e5ua69scxhvyma568nvguqccrv4cc9n4')).hex() == '79fbfc3f34e7745860d76137da68f362380c606c'
    assert script_pubkey_to_script_hash(addr_to_script('3F3aZJZDuhixB4GfTgc1b9KFXjcaDAPF53')).hex() == '927d321c01a1d2e22d972220211086d258ece169'
    assert script_pubkey_to_script_hash(addr_to_script('tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7')).hex() == '1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262'

    # p2pk test 
    script_pubkey = bytes.fromhex('4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac')
    assert script_to_addr(script_pubkey) == '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
    assert script_pubkey_to_pubkey_hash(script_pubkey).hex() == '62e907b15cbf27d5425399ebf6f0fb50ebb88f18'
    
    sizes = [(6, '06'), (256, 'fd0001'), (80000, 'fe80380100'), (10000000000, 'ff00e40b5402000000')]
    for size, size_ser in sizes:
        assert CompactSize.serialize(size).hex() == size_ser, size
        assert CompactSize.deserialize_hex(size_ser) == size, size
    with assert_exception(SerializationError):
        CompactSize.serialize(-1)
    
    # Primitives test
    assert hash160('correct horse battery staple').hex() == 'cbfb7f6b1210f54ca694be694449f2918f193cb1'
    assert hmac_sha256('foo', 'bar').hex() == 'f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317'
    with assert_exception(ValueError):
        b58decode('5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3h0')
    with assert_exception(ValueError): 
        b58check_decode('5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hh')
    assert get_networks()['mainnet'] == get_network('mainnet') == mainnet
    assert get_networks()['testnet'] == get_network('testnet') == testnet
    assert testnet != mainnet
    for name, network in get_networks().items():
        assert name == str(network)
    assert addr_to_network('1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8') == 'mainnet'
    
    assert (mainnet, 'wif') == grok('5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS')
    print(grok('5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hh'))
    assert (mainnet, 'p2wpkh') == grok('BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4')
    assert (testnet, 'p2wsh') == grok('tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7')
    assert (None, '' ) == grok('bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx')
    assert (None, '') == grok('1pzry9x0s0muk')

    # Sign/verify test
    exponent = sha256(b'correct horse battery staple')
    priv = PrivateKey(exponent)
    pubkey_in = priv.pub().encode('bin')
    msg32 = sha256(b'hello world')
    sig_der = priv.ecdsa_raw_sign(msg32)
    sig = bitcoin.ecdsa_raw_sign(msg32, exponent)
    assert sig_der.hex() == bitcoin.der_encode_sig(*sig)
    assert priv.pub().ecdsa_raw_verify(msg32, sig_der)
    assert not PrivateKey(b'\x01' * 32).pub().ecdsa_raw_verify(msg32, sig_der)

    priv = PrivateKey('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1')
    assert priv.pub().encode('pkh').hex() == '9a1c78a507689f6f54b847ad1cef1e614ee23f1e'
    with assert_exception(ValueError):
        priv.encode('no such format')
    with assert_exception(InvalidKeyException):
        PrivateKey('1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8')
    
    xpriv = HDPrivateKey.from_seed(b'hello').encode()
    assert bitcoin.bip32_master_key(b'hello') == xpriv
    assert grok(xpriv) == (mainnet, 'xpriv.p2pkh')
    assert grok('5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS') == (mainnet, 'wif')
    
    p = HDPrivateKey.from_xpriv(xpriv)
    assert p.encode() == xpriv
    assert p.xpub().encode() == bitcoin.bip32_privtopub(xpriv)
    #print(xpriv)    
    assert p.derive(0).encode() == bitcoin.bip32_ckd(xpriv, 0)
    with assert_exception(ValueError):
        p.derive(-1)
    
    xpub = 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
    p = HDPublicKey.from_xpub(xpub)
    assert p.encode() == xpub
    assert p.derive(0).encode() == bitcoin.bip32_ckd(xpub, 0)
    with assert_exception(ValueError):
        p.derive(2 ** 31 + 1)
    
    with assert_exception(ValueError):
        HDPrivateKey.from_xpriv(xpub)

        
    seed = 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542'
    xpriv = 'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9'
    assert HDPrivateKey.from_seed(bytes.fromhex(seed)).derive(0).derive(2147483647 + 2**31).encode() == xpriv
    
    xpub = 'xpub661MyMwAqRbcGnMkaTx2594P9EDuiEqMq25PM2aeG6UmwzaohgA6uDmNsvSUV8ubqwA3Wpste1hg69XHgjUuCD5HLcEp2QPzyV1HMrPppsL'
    p = HDPublicKey.from_xpub(xpub)
    key_id = bytes.fromhex('042b92b4a83177d3c27862aab25e4b527993a04fef2c070fc3740fb840bf4ec2')
    assert p.derive(key_id).encode() == 'xpub661MyMwAqRbcGT3mNnUVq2WTxLPfFnyoug6svzN8xZ1yoWVzBBvSbYtg8cKx79SHHRTsgueC3qJYJqmDi5osPtbzvHJ85raN3hcHHrhmz1i'
    
    exponent = hashlib.sha256(b'correct horse battery staple').digest()
    pk = '5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS'
    priv = PrivateKey(pk)
    #print(priv)
    assert priv.encode('hex') == bitcoin.encode_privkey(pk, 'hex')
    assert priv.encode('wif') == bitcoin.encode_privkey(pk, 'wif')
    assert priv.encode('wif', compressed=True) == bitcoin.encode_privkey(pk, 'wif_compressed')
    assert priv.encode('wif', network=testnet) == bitcoin.encode_privkey(pk, 'wif', 0x6f)

    assert priv.pub().encode('p2pkh') == bitcoin.privtoaddr(pk)
    assert priv.pub().encode('hex') == bitcoin.privtopub(pk)
    assert priv.pub().point() == bitcoin.decode_pubkey(bitcoin.privtopub(pk))
    
    pubkey = priv.pub().encode('hex')
    assert (priv.pub() * 2).encode('hex') == bitcoin.add_pubkeys(pubkey, pubkey)
    bp = bitcoin.encode_pubkey(bitcoin.G, 'hex')
    assert (priv.pub() + 2).encode('hex') == bitcoin.add_pubkeys(bitcoin.add_pubkeys(pubkey, bp), bp)

    pk = b'\xee' * 32
    pkc = bitcoin.encode_privkey(pk, 'bin_compressed')
    assert PrivateKey(pk).pub().encode('p2pkh', compressed=True) == bitcoin.privtoaddr(pkc)
    
    # segwit tests
    t = Transaction.deserialize_hex('02000000000101a5bc96c36f1ae114a982196539c892a83fc0872e8ec17bddf3a58b87f732e8f50100000017160014e6a56184802dde75a7d99abffa1f52a10e2f1100feffffff0200e1f505000000001976a9140f560846934f203108348aa3866e1fe3185971df88ac7c557d920000000017a914eccc640fca9aa4eb88cf1fb7015f5ec279941bf5870247304402203623eb0ca85920c70687d7943b5e16271dd260e4a4dbd52940ba22f975b01f3902206b29d06c65a703b24da08e3ef03e548f7453024a32aa195469ff4253c5824bee012103f404f9b2baa48322792adba5d333afe7f66f1488955b16311a17e6a6734a9a72c3000000')
    assert t.hash() == 'dc142832892a10fb14d2409c8f771223515c9d6073ef018f6d6261a6b26831ee'
    assert len(t.inputs[0].witness) == 2
    tx_hex = '010000000001018d6f79531a0468b7fba03a6ab3ae1cec4b1326219dce51199453de332fda8d4e0000000000fdffffff0122ca010000000000220020c445adf3a53f0079d3cad994dffc9044e2197f460b2d65d144c968366cdad021feffffffff7dd50100000000000000050047304402204a6cf9880846bf7ee4f46d86c5f657128ae0e8c2c21c7456e02a741bca104dce02202a199b3a220ce56ed3a99330228d7c5bf2d3adff785b602909289eaeb800ce820101ff01fffd0201524c53ff02aa7ed3015e0ede1480000001eee56ec14bd0108027229918303472f7e0ec6adf139fb0c994d70e18faea9d4a027fc28ff26d55d1dd232fd9b931c09c80e5611718854e047aa3f5892e676f84d7000000004c53ff02aa7ed301532d06d580000001415e0d04a848bd9b86a681ce02561a59d9d8c5b8b593b3f2f6c5dcbe72b46cce02984685b96551b7634dc58ec6435946a313f13f53b631a118b1b2126fc8b484a5000000004c53ff02aa7ed301a12768c680000001bf3650dcbb48104acad66840fb2e6e2f8cc80d617766379c1ac5ea9d8d574bb702c8869066c231b0cca9ae2536bb82dbe96241d05f0a1f5dbcd78897243f16306f0000000053ae76710800'
    t = Transaction.deserialize_hex(tx_hex)
    assert t.inputs[0].value == 120189
    assert t.inputs[0].witness_version == 0
    assert not t.is_coinbase()
    assert len(t.inputs[0].witness) == 5
    
    tx_hex = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08044c86041b020602ffffffff0100f2052a010000004341041b0e8c2567c12536aa13357b79a073dc4444acb83c4ec7a0e2f99dd7457516c5817242da796924ca4e99947d087fedf9ce467cb9f7c6287078f801df276fdf84ac00000000'
    t = Transaction.deserialize_hex(tx_hex)
    assert t.is_coinbase()
    
    version = bytes.fromhex('721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001')

    print(Version.deserialize_bytes(version))

    block = bytes.fromhex('01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d010effffffff0100f2052a0100000043410494b9d3e76c5b1629ecf97fff95d7a4bbdac87cc26099ada28066c6ff1eb9191223cd897194a08d0c2726c5747f1db49e8cf90e75dc3e3550ae9b30086f3cd5aaac00000000')

    tx = bytes.fromhex('0100000002d9a798f55acfd8b245039b0c990e0c735fe890afe0cc79718d35b96216fe71ef010000008b48304502206cca1c1b11e348a6efaf71d87b8c2f05851762b13a03791539d3bc32ac479c700221008d644b7fcc213f9a31a65a3209a7b437d4e058d462c4479a0741343916d2470e01410405bf6eb4c9e34d1049fd8b54810ad53814e437e8a056716a5efb5f91aaf45f1b478325307c09a232c2ec022443c8f23e92ef3065846c5d6846747c969563d441ffffffffc15b54318f943b928215f30cd19c02e89dfa25d8add72d79810557d9ca30889b010000008c493046022100b34d28f33dae6b4f97331fd97b4174f36392990ab721a8e75d66841eef6c677302210087bd2f26655e4886c21e49c03ab8901182d6236ad857f816a3da28a40313e9b6014104bd031c8f3bc3ba550c588c7f6935228c0458cfbf645fcdd188e8eb94db3253957f4baaef74669d9847b4ffb8687d0aa7551f45de72439a2d43d436152977b0acffffffff0380969800000000001976a9142c46ea44103a529d6686f0ca0978ab9be60daf3f88ac2e3d0000000000001976a9146ea087df3ee4216e20bf37888d160fb92e71e54588ac58290200000000001976a914474f0c0c0c93b4ae40420c126dbd9c8c675ae41f88ac00000000')

    b = BlockHeader(1, b'\x01' * 32, b'\02' * 32, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)
    print(b.serialize(b).hex())

    z = io.BytesIO(block)
    b = BlockHeader.deserialize(z)
    print(b)
    print(b.serialize(b).hex())


    l32 = List(UnsignedInteger(16))
    b = l32.serialize([1,2,3,666])
    print(b.hex())
    print(l32.deserialize(io.BytesIO(b)))
    # print(l32.decode(b))

    tx = Transaction.deserialize_bytes(tx)
    print(tx)
    
    for o in tx.outputs:
        p = parse_script(o.script)
        print(p)
        print(o.script.hex())
        print(compile_script(p) == o.script)
        print(script_pubkey_to_pubkey_hash(o.script).hex())
        print(b58check_encode(script_pubkey_to_pubkey_hash(o.script)))

    s = b'@' * 10001
    VarBytestring.serialize(s)
    
    # TX Signing Test
    inputs = [
        {'txid': '97f7c7d8ac85e40c255f8a7ffb6cd9a68f3a94d2e93e8bfa08f977b92e55465e', 'n': 0},
        {'txid': '00f7c7d8ac85e40c255f8a7ffb6cd9a68f3a94d2e93e8bfa08f977b92e55465e', 'n': 1}]
    addr = '16iw1MQ1sy1DtRPYw3ao1bCamoyBJtRB4t'
    outputs = {addr: 90000}
    tx = mktx(inputs, outputs)
    print('unsigned', tx)
    priv = PrivateKey('97f7c7d8ac85e40c255f8a7ffb6cd9a68f3a94d2e93e8bfa08f977b92e55465e')
    spending_addr = priv.pub().encode('p2pkh')
    print('spending_addr', spending_addr)
    script_pubkey = addr_to_script(spending_addr)
    print('script_pubkey', script_pubkey, script_pubkey.hex())
    #tx.sign_input(0, script_pubkey, priv)
    tx.sign(priv)
    
    #print(tx.input[0])
    print('signed', tx)
    signed = Transaction.serialize(tx)
    print('signed', signed.hex())
    print('signed', tx.hash())
    
    
    bh_ser_hex = '010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299'
    bh = BlockHeader.deserialize_hex(bh_ser_hex)
    assert serialize(bh).hex() == bh_ser_hex
    assert bh.__dict__ == {'bits': 486604799,
        'merkle_root': b'\x0e>#W\xe8\x06\xb6\xcd\xb1\xf7\x0bT\xc3\xa3\xa1{g\x14\xee\x1f\x0eh\xbe\xbbD\xa7K\x1e\xfdQ \x98',
        'nonce': 2573394689,
        'previous': b'\x00\x00\x00\x00\x00\x19\xd6h\x9c\x08Z\xe1e\x83\x1e\x93O\xf7c\xaeF\xa2\xa6\xc1r\xb3\xf1\xb6\n\x8c\xe2o',
        'time': 1231469665,
        'version': 1}
    
    
    chain = BitcoindChain(os.environ['BITCOIND_URL'])
    
    '''
    info = service.getinfo()
    blockhash = service.getblockhash(info['blocks'])
    block = requests.get('http://madness:8332/rest/block/%s.bin' % blockhash).content
    block = Block.deserialize_bytes(block)
    print([b.lock_time for b in block.txs])
    print(len(block.txs))
    n = len([1 for b in block.txs if b.lock_time])
    print(n)
    '''

    txid = '12e4819519ef7ff9af742bb31c5d6c44e969053bdb1dfbc476a7b43424a94e7c'
    tx = chain.get_tx(txid)
    print(tx)
    for n, input in enumerate(tx.inputs):    
        script = chain.get_txout(input.txid.hex(), input.n)
        sig, pubkey = parse_script(input.script)
        print('verify', n, tx.verify_input(n, script, sig, pubkey))
    
    
    service = JsonRpcProxy(os.environ['BITCOIND_URL'])
    print(service.getblockchaininfo())
    with assert_exception(JsonRpcException):
        service.nosuchmethod('unneeded argument')
    with assert_exception(JsonRpcException):
        service.getblockchaininfo('unneeded argument')
    
    txid = '12e4819519ef7ff9af742bb31c5d6c44e969053bdb1dfbc476a7b43424a94e7c'
    tx_hex = service.getrawtransaction(txid)
    tx = Transaction.deserialize_hex(tx_hex)
    assert tx.hex() == tx_hex
    assert tx.hash() == txid == txhash(serialize(tx).hex())
    with assert_exception(ValueError):
        txhash(0)
    
    with assert_exception(JsonRpcException):
        JsonRpcProxy(os.environ['BITCOIND_URL'] + '/doesnotexist', verify=False).getblockchaininfo()
    
    rpc_inputs = [{
        'txid': i['txid'],
        'vout': i['n'],
        'scriptPubKey': script_pubkey.hex(),
    } for i in inputs]
    print(rpc_inputs)
    print(service.signrawtransactionwithwallet(signed.hex(), rpc_inputs))
    
    # TX Multisigning Test
    hd_priv = HDPrivateKey.from_seed('test')
    privs = [hd_priv.derive(i).priv() for i in range(3)]
    pubs = [p.pub() for p in privs]
    print(privs)
    print(pubs)
    
    redeem_script = create_redeem_script(3, pubs)
    print('redeem_script', redeem_script.hex())
    print(parse_script(redeem_script, True))
    inputs = [{'txid': '97f7c7d8ac85e40c255f8a7ffb6cd9a68f3a94d2e93e8bfa08f977b92e55465e', 'n': 0}]
    addr = '16iw1MQ1sy1DtRPYw3ao1bCamoyBJtRB4t'
    outputs = {addr: 90000}
    tx = mktx(inputs, outputs)
    
    # redeem_script to p2sh_script_pubkey
    script_pubkey = compile_script([Script.OP_HASH160, hash160(redeem_script), Script.OP_EQUAL])
    
    #script_sig = compile_script([Script.OP_0, Script.OP_0, Script.OP_0, redeem_script])
    script_sig = compile_script([Script.OP_0, Script.OP_0, redeem_script])
    tx.inputs[0].script = script_sig
    print('complete', tx.multisign_input(0, privs[2]))
    print(tx)
    print('complete', tx.multisign_input(0, privs[1]))
    print(tx)
    #print(Transaction.serialize(tx).hex())
    print('complete', tx.multisign_input(0, privs[0]))
    print(tx)
    #print(Transaction.serialize(tx).hex())
    
    rpc_inputs = [{
        'txid': i['txid'],
        'vout': i['n'],
        'scriptPubKey': script_pubkey.hex(),
        'redeemScript': redeem_script.hex(),
    } for i in inputs]
    print(rpc_inputs)
    print(json.dumps(service.signrawtransactionwithwallet(Transaction.serialize(tx).hex(), rpc_inputs), indent=1))
    
    '''
    info = service.getinfo()
    blockhash = service.getblockhash(info['blocks'])
    block = requests.get('http://madness:8332/rest/block/%s.bin' % blockhash).content
    block = Block.deserialize_bytes(block)
    print([b.lock_time for b in block.txs])
    print(len(block.txs))
    n = len([1 for b in block.txs if b.lock_time])
    print(n)
    '''
    
    # Test derive_compact_xpub bip32
    xpub = bitcoin.bip32_privtopub(bitcoin.bip32_master_key(b'test'))
    path = [1, 7]
    pub = bitcoin.bip32_descend(xpub, *path)
    compact_xpub = b'\xff' + bitcoin.changebase(xpub, 58, 256)[:-4] + path[0].to_bytes(2, 'little') + path[1].to_bytes(2, 'little')
    parts = derive_compact_xpub(compact_xpub)
    assert parts[0].encode() == xpub
    assert parts[1] == path
    assert parts[2].encode('hex') == pub
    # test electrum
    master_public_key = '78d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455'
    compact_xpub = b'\xfe' + master_public_key.encode('utf-8')
    compact_xpub += path[0].to_bytes(2, 'little') + path[1].to_bytes(2, 'little')
    parts = derive_compact_xpub(compact_xpub)
    assert parts[2].encode('hex') == bitcoin.electrum_pubkey(master_public_key, path[1], path[0])
    
    # Test multisign compact
    
    xprivs = [HDPrivateKey.from_seed(b'key %d' % i) for i in range(3)]
    paths = [[1, i] for i in range(3)]
    threshold = 2
    compact_redeem_script = []
    compact_redeem_script.append(int_to_opcode(threshold))
    pubs = []
    for xpriv, path in zip(xprivs, paths):
        compact_xpub = xpriv.xpub().encode_compact(path)
        compact_redeem_script.append(compact_xpub)
        print(xpriv.xpub().derive_path(path).pub().encode('hex'))
        parts = derive_compact_xpub(compact_xpub)
        print(parts[2].encode('hex'))
    compact_redeem_script.append(int_to_opcode(len(xprivs)))
    compact_redeem_script.append(Script.OP_CHECKMULTISIG)
    print(compact_redeem_script)
    compact_redeem_script = compile_script(compact_redeem_script)
    print(compact_redeem_script.hex())    
    
    inputs = [{'txid': '97f7c7d8ac85e40c255f8a7ffb6cd9a68f3a94d2e93e8bfa08f977b92e55465e', 'n': 0}]
    addr = '16iw1MQ1sy1DtRPYw3ao1bCamoyBJtRB4t'
    outputs = {addr: 90000}
    tx = mktx(inputs, outputs)
    script_sig = [Script.OP_0, NO_SIGNATURE, NO_SIGNATURE, NO_SIGNATURE, compact_redeem_script]
    print('script_sig', script_sig)
    tx.inputs[0].script = compile_script(script_sig)
    complete = tx.multisign_compact_input(0, xprivs[2])
    print(complete)
    complete = tx.multisign_compact_input(0, xprivs[0])
    print(complete)
    print(tx)
    #complete = tx.multisign_compact_input(0, xprivs[1])
    #print(complete)
    #print(tx)
    
    redeem_script_final = parse_script(tx.inputs[0].script)[-1]
    script_pubkey = compile_script([Script.OP_HASH160, hash160(redeem_script_final), Script.OP_EQUAL])
    print(parse_script(tx.inputs[0].script, True))
    rpc_inputs = [{
        'txid': i['txid'],
        'vout': i['n'],
        'scriptPubKey': script_pubkey.hex(),
        'redeemScript': redeem_script_final.hex(),
    } for i in inputs]
    print(rpc_inputs)
    print(json.dumps(service.signrawtransactionwithwallet(Transaction.serialize(tx).hex(), rpc_inputs), indent=1))
    
    
    hostname, port = 'us.electrum.be', 50001
    hostname, port = '185.64.116.15', 50001
    with assert_exception(ConnectionError):
        ElectrumInterface(hostname, 60000)
    electrum = ElectrumInterface(hostname, port)
    assert electrum.connected()
    print(electrum.get_response('blockchain.headers.subscribe', []))
    r = electrum.get_response('blockchain.transaction.get', ['f1fb5068895cfe7079132616258c6e7a7f6d0bbf11301f9f57b3bf12e5eaa676', True])
    print(json.dumps(r, indent=1))
    scripthash = 'b2e530d5e86f07439c42039776b61a261a5bc472d88eba6eb64bd2c285b20f4e'
    assert electrum_script_hash('1MnpxUtNed62JroUg9UfZMVcEPrmCwER1J') == scripthash
    print(electrum.get_response('blockchain.scripthash.get_balance', [scripthash]))
    print(electrum.get_response('blockchain.scripthash.get_history', [scripthash]))
    print(electrum.get_response('blockchain.scripthash.listunspent', [scripthash]))
    print(electrum.get_response('blockchain.block.header', [1]))
    print(electrum.get_response('blockchain.estimatefee', [2]))
    print(electrum.get_response('blockchain.relayfee', []))
    

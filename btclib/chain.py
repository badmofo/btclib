import json
from decimal import Decimal
import requests
from btclib.jsonrpc import JsonRpcProxy
from btclib.base import Transaction

class BitcoindChain(object):
    def __init__(self, url):
        self.service = JsonRpcProxy(url)
    
    def get_tx(self, txid):
        tx_hex = self.service.getrawtransaction(txid)
        if tx_hex:
            return Transaction.deserialize_bytes(bytes.fromhex(tx_hex))
        
    def get_txout(self, txid, n):
        tx = self.get_tx(txid)
        if tx:
            return tx.outputs[n].script

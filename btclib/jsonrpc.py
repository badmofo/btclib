import requests
import requests.utils
import collections
import decimal
import urllib.parse
import simplejson as json


def extract_auth_from_url(url):
    parts = urllib.parse.urlparse(url)
    return parts.username, parts.password, requests.utils.urldefragauth(url)

def extract_auth_from_url2(url):
    scheme, netloc, path, query, fragment = urllib.parse.urlsplit(url)
    user_password, host_port = urllib.parse.splituser(netloc)
    user, password = urllib.parse.splitpasswd(user_password) if user_password else (None, None)
    return user, password, urllib.parse.urlunsplit([scheme, host_port, path, query, fragment])

class JsonRpcException(Exception):
    def __init__(self, message, code=None):
        self.code = code
        super(JsonRpcException, self).__init__(message)

class JsonRpcProxy(object):
    def __init__(self, url, verify=True):
        username, password, url = extract_auth_from_url(url)
        self.url = url
        self.session = requests.session()
        self.session.verify = verify
        if not verify:
            requests.packages.urllib3.disable_warnings()
        if username:
            self.session.auth = (username, password)
        self.n = 1

    def __getattr__(self, name):
        def f(*args):
            data = {
                'jsonrpc': '2.0',
                'method': name,
                'params': args,
                'id': self.n
            }
            self.n += 1
            try:
                r = self.session.post(self.url, data=json.dumps(data))
                if not r.headers['Content-Type'].startswith('application/json'):
                    r.raise_for_status()
            except requests.RequestException as e:
                raise JsonRpcException(str(e))
            r = json.loads(r.text, parse_float=decimal.Decimal, object_pairs_hook=collections.OrderedDict)
            if r.get('error'):
                raise JsonRpcException(r['error']['message'], r['error']['code'])
            return r['result']
        return f

from pyramid.security import Allow
from pyramid.security import Authenticated
from pyramid.security import DENY_ALL
from yasso.encryption import Decryptor
from yasso.encryption import Encryptor
from yasso.encryption import KeyReader
from yasso.encryption import KeyWriter
import hashlib
import re


class AuthorizationServer(object):

    __acl__ = (
        (Allow, Authenticated, 'use_oauth'),
        (Allow, 'yasso.client', 'get_token'),
        (Allow, 'yasso.bearer', 'get_user_info'),
        DENY_ALL,
    )

    def __init__(self, config_file):
        self.clients = {}  # client_id: Client
        key_dir = 'XXX'
        key_writer = KeyWriter(key_dir)
        self.encrypt = Encryptor(key_writer)
        key_reader = KeyReader(key_dir)
        self.decrypt = Decryptor(key_reader)


class Client(object):

    def __init__(self,
            client_id,
            secret=None,
            secret_sha256=None,
            redirect_uri_expr=None,
            default_redirect_uri=None):
        assert isinstance(client_id, basestring)
        self.client_id = client_id
        if secret_sha256 is None:
            secret_sha256 = hashlib.sha256(secret).hexdigest()
        self.secret_sha256 = secret_sha256.lower()
        if redirect_uri_expr and not hasattr(redirect_uri_expr, 'match'):
            redirect_uri_expr = re.compile(redirect_uri_expr)
        self.redirect_uri_expr = redirect_uri_expr
        self.default_redirect_uri = default_redirect_uri

    def check_secret(self, secret):
        h = hashlib.sha256(secret).hexdigest().lower()
        return h == self.secret_sha256

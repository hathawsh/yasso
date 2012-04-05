
from ConfigParser import ConfigParser
from pyramid.security import Allow
from pyramid.security import Authenticated
from pyramid.security import DENY_ALL
from randenc import RandomEncryption
import hashlib
import os
import re


class AuthorizationServer(object):

    __acl__ = (
        (Allow, 'oauth.bearer', 'userinfo'),
        DENY_ALL,
    )

    def __init__(self, config_file):
        dirname = os.path.dirname(config_file)
        self.cp = ConfigParser(defaults={
            'here': dirname,
            '__file__': config_file,
        })
        self.cp.read([config_file])

        key_dir = os.path.abspath(self.cp.get('randenc', 'dir'))
        freshness = int(self.get_option('randenc', 'freshness', 300))
        max_age = int(self.get_option('randenc', 'max_age', 3600))
        max_future = int(self.get_option('randenc', 'max_future', 300))
        randenc = RandomEncryption(key_dir,
            freshness=freshness, max_age=max_age, max_future=max_future)
        self.randenc = randenc
        self.encrypt = randenc.encrypt
        self.decrypt = randenc.decrypt

        # Set up Clients from the config file.
        self.clients = {}  # client_id: Client
        prefix = 'client:'
        for section in self.cp.sections():
            if section.startswith(prefix):
                client_id = self.get_option(section, 'id')
                if not client_id:
                    client_id = section[len(prefix):]
                client = Client(
                    client_id=client_id,
                    secret=self.get_option(section, 'secret'),
                    secret_sha256=self.get_option(section, 'secret_sha256'),
                    redirect_uri_expr=self.get_option(
                        section, 'redirect_uri_expr'),
                    default_redirect_uri = self.get_option(
                        section, 'default_redirect_uri'),
                )
                self.clients[client.client_id] = client

        self.models = {
            'authorize': AuthorizeEndpoint(self, 'authorize'),
            'token': TokenEndpoint(self, 'token'),
        }

    def get_option(self, section, name, default=None):
        if self.cp.has_option(section, name):
            return self.cp.get(section, name)
        else:
            return default

    def __getitem__(self, name):
        return self.models[name]


class Client(object):

    def __init__(self,
            client_id,
            secret=None,
            secret_sha256=None,
            redirect_uri_expr=None,
            default_redirect_uri=None):
        self.client_id = client_id
        if secret_sha256 is None:
            if secret is None:
                raise ValueError(
                    "Client %s: Either secret or secret_sha256 is required.")
            secret_sha256 = hashlib.sha256(secret).hexdigest()
        self.secret_sha256 = secret_sha256.lower()
        if redirect_uri_expr and not hasattr(redirect_uri_expr, 'match'):
            redirect_uri_expr = re.compile(redirect_uri_expr)
        self.redirect_uri_expr = redirect_uri_expr
        self.default_redirect_uri = default_redirect_uri

    def check_secret(self, secret):
        h = hashlib.sha256(secret).hexdigest().lower()
        return h == self.secret_sha256


class AuthorizeEndpoint(object):

    __acl__ = (
        (Allow, Authenticated, 'use_oauth'),
        DENY_ALL,
    )

    def __init__(self, parent, name):
        self.__parent__ = parent
        self.__name__ = name


class TokenEndpoint(object):

    __acl__ = (
        (Allow, 'oauth.client', 'get_token'),
        DENY_ALL,
    )

    def __init__(self, parent, name):
        self.__parent__ = parent
        self.__name__ = name

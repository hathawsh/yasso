
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
        DENY_ALL,
    )

    def __init__(self, settings):
        key_dir = os.path.abspath(settings['randenc.dir'])
        freshness = int(settings.get('randenc.freshness', 300))
        max_age = int(settings.get('randenc.max_age', 3600))
        max_future = int(settings.get('randenc.max_future', 300))
        randenc = RandomEncryption(key_dir,
            freshness=freshness, max_age=max_age, max_future=max_future)
        self.randenc = randenc
        self.encrypt = randenc.encrypt
        self.decrypt = randenc.decrypt

        client_config_file = settings['client_config_file']
        self.build_client_map(client_config_file)

        self.models = {
            'authorize': AuthorizeEndpoint(self, 'authorize'),
            'token': TokenEndpoint(self, 'token'),
            'resource': ResourceEndpoint(self, 'resource'),
        }

    def build_client_map(self, client_config_file):
        cp = ConfigParser()
        cp.read([client_config_file])
        clients = {}  # client_id: Client

        for section in cp.sections():

            def get_option(name, default=None):
                if cp.has_option(section, name):
                    return cp.get(section, name)
                else:
                    return default

            client = Client(
                client_id=section,
                secret=get_option('secret'),
                secret_sha256=get_option('secret_sha256'),
                redirect_uri_expr=get_option('redirect_uri_expr'),
                default_redirect_uri=get_option('default_redirect_uri'),
            )
            clients[client.client_id] = client

        self.clients = clients

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
        (Allow, Authenticated, 'authorize'),
        DENY_ALL,
    )

    def __init__(self, parent, name):
        self.__parent__ = parent
        self.__name__ = name


class TokenEndpoint(object):

    __acl__ = (
        (Allow, 'oauth.client', 'token'),
        DENY_ALL,
    )

    def __init__(self, parent, name):
        self.__parent__ = parent
        self.__name__ = name


class ResourceEndpoint(object):

    __acl__ = (
        (Allow, 'oauth.bearer', 'userinfo'),
        DENY_ALL,
    )

    def __init__(self, parent, name):
        self.__parent__ = parent
        self.__name__ = name

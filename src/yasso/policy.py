
from pyramid.interfaces import IAuthenticationPolicy
from pyramid.security import Authenticated
from pyramid.security import Everyone
from randenc.enc import DecryptionError
from zope.interface import implements
import base64
import logging
import re
import time

log = logging.getLogger(__name__)


class ClientAuthenticationPolicy(object):
    """Authenticate OAuth2 clients using client_id and client_secret.

    This is used for the token endpoint.
    """
    implements(IAuthenticationPolicy)

    def __init__(self, root_factory):
        self.root_factory = root_factory

    def get_credentials(self, request):
        """Return (client_id, secret) from the request."""
        header = request.headers.get('Authorization')
        if header:
            match = re.match(r'Basic\s+([^\s]+)', header, re.I)
            if match:
                value = match.group(1)
                try:
                    client_id, secret = base64.decodestring(value).split(':')
                except ValueError, e:
                    log.warning("Authorization header parse error; "
                        "ignoring: %s", e)
                else:
                    return client_id, secret

        client_id = request.POST.get('client_id')
        secret = request.POST.get('client_secret')
        if client_id:
            return client_id, secret
        return None, None

    def authenticated_userid(self, request):
        client_id, secret = self.get_credentials(request)
        if client_id is None or not secret:
            return None
        root = self.root_factory(request)
        client = root.clients.get(client_id)
        if client is None:
            return None
        if not client.check_secret(secret):
            return None
        return client_id

    def unauthenticated_userid(self, request):
        return self.get_credentials(request)[0]

    def effective_principals(self, request):
        effective_principals = [Everyone]
        userid = self.authenticated_userid(request)
        if userid is None:
            return effective_principals
        effective_principals.append(Authenticated)
        effective_principals.append('oauth.client')
        effective_principals.append(userid)
        return effective_principals

    def remember(self, request, principal, **kw):
        return []

    def forget(self, request):
        return []


class BearerAuthenticationPolicy(object):
    """Authenticate OAuth2 clients using access_token.

    This is used for resources.

    Decrypted tokens contain:

    ['t', created_time, client_id, userid]
    """
    implements(IAuthenticationPolicy)

    def __init__(self, root_factory, max_age=3600):
        self.root_factory = root_factory
        self.max_age = max_age

    def decrypt_token(self, request):
        """Return token info if the request has a valid token.

        Raise DecryptionError if the token is bad or expired.
        """
        access_token = None
        header = request.headers.get('Authorization')
        if header:
            match = re.match(r'Bearer\s+([^\s]+)', header, re.I)
            if match:
                access_token = match.group(1)

        if not access_token:
            access_token = request.params.get('access_token')
        if not access_token:
            raise DecryptionError("No access token provided")
        root = self.root_factory(request)
        content = root.decrypt(access_token)

        if content[0] != 't':
            raise DecryptionError("The given code is not an access token")

        age = time.time() - content[1]
        if age >= self.max_age:
            raise DecryptionError("The token has expired")

        return content

    def unauthenticated_userid(self, request):
        """ Return the *unauthenticated* userid.  This method performs the
        same duty as ``authenticated_userid`` but is permitted to return the
        userid based only on data present in the request; it needn't (and
        shouldn't) check any persistent store to ensure that the user record
        related to the request userid exists."""
        try:
            content = self.decrypt_token(request)
        except DecryptionError, e:
            log.debug("DecryptionError: %s", e)
            return None
        return content[3]

    def authenticated_userid(self, request):
        """ Return the authenticated userid or ``None`` if no authenticated
        userid can be found. This method of the policy should ensure that a
        record exists in whatever persistent store is used related to the
        user (the user should not have been deleted); if a record associated
        with the current id does not exist in a persistent store, it should
        return ``None``."""
        try:
            _, _, client_id, userid = self.decrypt_token(request)
        except DecryptionError, e:
            log.debug("DecryptionError: %s", e)
            return None

        root = self.root_factory(request)
        client = root.clients.get(client_id)
        if client is None:
            return None

        request.environ['yasso.client'] = client
        return userid

    def effective_principals(self, request):
        effective_principals = [Everyone]
        userid = self.authenticated_userid(request)
        if userid is None:
            return effective_principals
        effective_principals.append(Authenticated)
        effective_principals.append('oauth.bearer')
        effective_principals.append(userid)
        return effective_principals

    def remember(self, request, principal, **kw):
        return []

    def forget(self, request):
        return []


"""Views for the token application."""

from pyramid.httpexceptions import HTTPForbidden
from pyramid.httpexceptions import HTTPUnauthorized
from pyramid.security import authenticated_userid
from pyramid.traversal import find_interface
from pyramid.view import forbidden_view_config
from pyramid.view import view_config
from randenc.enc import DecryptionError
from yasso.models import AuthorizationServer
from yasso.models import TokenEndpoint
import time


class TokenEndpointError(Exception):
    def __init__(self, error, description):
        self.error = error
        self.description = description


@view_config(context=TokenEndpoint, permission='token', renderer='json')
def token_view(context, request):
    """Get an access token."""
    authz = find_interface(context, AuthorizationServer)
    try:
        try:
            grant_type = request.POST['grant_type']
            code = request.POST['code']
            redirect_uri = request.POST.get('redirect_uri', '')
        except KeyError, e:
            raise TokenEndpointError('invalid_request', 'Required: %s' % e)

        if grant_type != 'authorization_code':
            raise TokenEndpointError('unsupported_grant_type',
                "Only the 'authentication_code' grant_type is supported.")

        client = authz.clients[authenticated_userid(request)]
        try:
            content = authz.decrypt(code)
        except DecryptionError, e:
            raise TokenEndpointError('invalid_grant', '%s' % e)
        if content[0] != 'c':
            raise TokenEndpointError('invalid_grant',
                "The code provided is not an authorization code.")
        (_, code_created, code_client_id, code_user_id,
            code_redirect_uri) = content

        if code_client_id != client.client_id:
            raise TokenEndpointError('invalid_grant', "Mismatched client_id.")

        age = time.time() - code_created
        max_auth_code_age = int(request.registry.settings.get(
            'max_auth_code_age', 600))
        if age >= max_auth_code_age:
            raise TokenEndpointError('invalid_grant',
                "The authorization code has expired.")

        if redirect_uri != code_redirect_uri:
            raise TokenEndpointError('invalid_grant',
                "Mismatched redirect_uri.")

        now = int(time.time())
        params = ['t', now, client.client_id, code_user_id]
        token = authz.encrypt(params)
        duration = authz.randenc.duration
        return {
            'access_token': token,
            'token_type': 'bearer',
            'expires_in': duration,
            'scope': '',
        }

    except TokenEndpointError, e:
        request.response.status = '400 Bad Request'
        return {
            'error': e.error,
            'error_description': e.description,
        }


@forbidden_view_config()
def basic_forbidden(request):
    realm = request.registry.settings.get('realm', request.host)
    auth_header = 'Basic realm="{0}"'.format(realm)
    headers = {'WWW-Authenticate': auth_header}
    if authenticated_userid(request) is not None:
        return HTTPForbidden(headers=headers)
    else:
        return HTTPUnauthorized(headers=headers)

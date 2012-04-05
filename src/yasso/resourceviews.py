
"""Views for the resource application."""

from pyramid.httpexceptions import HTTPForbidden
from pyramid.httpexceptions import HTTPUnauthorized
from pyramid.security import authenticated_userid
from pyramid.view import forbidden_view_config
from pyramid.view import view_config
from yasso.models import ResourceEndpoint


@view_config(name='userinfo', context=ResourceEndpoint, permission='userinfo',
        renderer='json')
def userinfo(request):
    client = request.environ.get('yasso.client')
    client_id = client.client_id if client is not None else None
    return {
        'userid': authenticated_userid(request),
        'client_id': client_id,
    }


@forbidden_view_config()
def bearer_forbidden(request):
    """A client failed to authenticate using an access token."""
    if authenticated_userid(request) is not None:
        # The currently authenticated user was forbidden access to something.
        error = 'insufficient_scope'
        klass = HTTPForbidden
    elif (request.params.get('access_token')
            or request.headers.get('Authorization')):
        # Credentials were provided, but they were not valid.
        error = 'invalid_token'
        klass = HTTPUnauthorized
    else:
        # No token was provided.
        error = None
        klass = HTTPUnauthorized

    realm = request.registry.settings.get('realm', request.host)
    auth_header = 'Bearer realm="{0}"'.format(realm)
    if error:
        auth_header += ', error="{0}"'.format(error)
    headers = {'WWW-Authenticate': auth_header}
    return klass(headers=headers)

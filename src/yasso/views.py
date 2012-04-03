
from pyramid.security import authenticated_userid
from pyramid.view import view_config
from yasso.models import AuthorizationServer


@view_config(context=AuthorizationServer,
    permission='userinfo', renderer='json')
def userinfo(request):
    client = request.environ.get('yasso.client')
    client_id = client.client_id if client is not None else None
    return {
        'userid': authenticated_userid(request),
        'client_id': client_id,
    }

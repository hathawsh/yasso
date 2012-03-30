
from pyramid.httpexceptions import HTTPFound
from pyramid.security import authenticated_userid
from pyramid.security import forget
from pyramid.url import resource_url
from pyramid.view import view_config
from yasso.models import User
from yasso.models import Yasso


@view_config(context=Yasso, renderer='templates/info.pt')
def info(yasso, request):
    userid = authenticated_userid(request)
    if userid:
        userid = unicode(userid)
        user = yasso.users.get(userid)
        if user is None:
            # Create a temporary User
            user = User(yasso.users, userid)
    else:
        user = None
    return {
        'title': yasso.title,
        'user': user,
    }


@view_config(context=Yasso, name='logout', renderer='templates/logout.pt')
def logout(yasso, request):
    headers = [('Cache-Control', 'no-cache')]
    if authenticated_userid(request):
        # Log out.
        if request.params.get('confirm-logout'):
            # The attempt to log out failed.
            return {'show': 'logout-failed'}
        headers.extend(forget(request))
        url = resource_url(yasso, request, request.view_name,
            query={'confirm-logout': 'true'})
        return HTTPFound(location=url, headers=headers)
    url = resource_url(yasso, request)
    return HTTPFound(location=url, headers=headers)

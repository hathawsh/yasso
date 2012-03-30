
from deform import Form
from pyramid.httpexceptions import HTTPFound
from pyramid.security import authenticated_userid
from pyramid.security import forget
from pyramid.url import resource_url
from pyramid.view import view_config
from yasso.models import User
from yasso.models import Yasso
import colander
from deform.exception import ValidationFailure
from pbkdf2 import crypt
from pyramid.security import remember


class LoginSchema(colander.MappingSchema):
    login = colander.SchemaNode(colander.String())
    password = colander.SchemaNode(colander.String())


@view_config(context=Yasso, renderer='templates/home.pt')
def home(yasso, request):
    userid = authenticated_userid(request)
    if userid:
        userid = unicode(userid)
        user = yasso.users.get(userid)
        if user is None:
            # Create a temporary User
            user = User(yasso.users, userid)
        return {
            'title': yasso.title,
            'user': user,
        }

    # Show a login form.
    schema = LoginSchema()
    form = Form(schema, buttons=('Sign In',), formid='login')
    error = None

    if request.POST.get('__formid__') == form.formid:
        # Form submitted.
        controls = request.POST.items()
        try:
            appstruct = form.validate(controls)
        except ValidationFailure, e:
            form = e
        else:
            userid = yasso.logins.get(appstruct['login'])
            if userid:
                user = yasso.users.get(userid)
                if user is not None and user.pwhash:
                    h = crypt(appstruct['password'], user.pwhash)
                    if h == user.pwhash:
                        # The password is correct.
                        headers = remember(request, userid)
                        url = resource_url(yasso, request)
                        return HTTPFound(location=url, headers=headers)
            error = u"Incorrect login or password."

    return {
        'title': yasso.title,
        'user': None,
        'form': form,
        'error': error,
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

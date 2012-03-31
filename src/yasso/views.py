
from deform import Form
from deform.exception import ValidationFailure
from deform.widget import HiddenWidget
from deform.widget import PasswordWidget
from pbkdf2 import crypt
from pyramid.httpexceptions import HTTPFound
from pyramid.renderers import render_to_response
from pyramid.security import authenticated_userid
from pyramid.security import forget
from pyramid.security import remember
from pyramid.url import resource_url
from pyramid.view import view_config
from urlparse import urljoin
from yasso.models import User
from yasso.models import Yasso
import colander
import logging
from colander import Invalid
import re
from urlparse import urlsplit
from yasso.models import AppUser
from pyramid.encode import urlencode
from urlparse import urlunsplit
from urlparse import parse_qsl
from markupsafe import Markup

log = logging.getLogger(__name__)


@view_config(context=Yasso, renderer='templates/home.pt')
def home(yasso, request):
    userid = authenticated_userid(request)
    if not userid:
        url = resource_url(yasso, request, 'login')
        return HTTPFound(location=url)

    userid = unicode(userid)
    user = yasso.users.get(userid)
    if user is None:
        # Create a temporary User object, but don't store it.
        user = User(yasso.users, userid)
    return {
        'title': yasso.title,
        'user': user,
    }


@colander.deferred
def came_from_default(node, kw):
    return kw['request'].params.get('came_from')


class LoginSchema(colander.MappingSchema):
    login = colander.SchemaNode(colander.String())
    password = colander.SchemaNode(
        colander.String(),
        widget=PasswordWidget(),
    )
    came_from = colander.SchemaNode(
        colander.String(),
        default=came_from_default,
        widget=HiddenWidget(),
    )


@view_config(context=Yasso, renderer='templates/login.pt')
def login(yasso, request):
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
            login = appstruct['login'].lower()
            userid = yasso.logins.get(login)
            if userid:
                user = yasso.users.get(userid)
                if user is not None and user.pwhash:
                    h = crypt(appstruct['password'], user.pwhash)
                    if h == user.pwhash:
                        # The password is correct.
                        headers = remember(request, userid)
                        base = resource_url(yasso, request)
                        came_from = appstruct['came_from']
                        if came_from:
                            url = urljoin(base, came_from)
                            if not url.startswith(base):
                                log.warning("Invalid came_from %r. "
                                    "(Must start with %r.)", came_from, base)
                                url = base
                        return HTTPFound(location=url, headers=headers)
                    else:
                        log.warning("Incorrect password. userid=%r, login=%r",
                            userid, login)
                else:
                    if user is None:
                        log.warning("No user found. userid=%r, login=%r",
                            userid, login)
                    else:
                        log.warning("No password set. userid=%r, login=%r",
                            userid, login)
            else:
                log.warning("No user found for login=%r", login)

            error = u"Incorrect login or password."

    return {
        'title': yasso.title,
        'user': None,
        'form': form,
        'error': error,
    }


@view_config(context=Yasso, name='logout')
def logout(yasso, request):
    headers = [('Cache-Control', 'no-cache')]
    if authenticated_userid(request):
        # Log out.
        if request.params.get('confirm-logout'):
            return render_to_response('templates/logout-failed.pt', {})
        headers.extend(forget(request))
        url = resource_url(yasso, request, request.view_name,
            query={'confirm-logout': 'true'})
        return HTTPFound(location=url, headers=headers)
    url = resource_url(yasso, request)
    return HTTPFound(location=url, headers=headers)


class AuthorizeParameters(colander.MappingSchema):
    """Parameters for the authorize endpoint.

    See OAuth 2 sections 4.1.1 and 4.2.1.
    """
    client_id = colander.SchemaNode(
        colander.Integer(),
        validator=colander.Range(min=1),
    )
    response_type = colander.SchemaNode(
        colander.String(),
        validator=colander.Length(min=1, max=50),
    )
    redirect_uri = colander.SchemaNode(
        colander.String(),
        validator=colander.Length(min=0, max=1024),
        missing=None,
    )
    scope = colander.SchemaNode(
        colander.String(),
        validator=colander.Length(min=0, max=1024),
        missing=None,
    )
    state = colander.SchemaNode(
        colander.String(),
        validator=colander.Length(min=0, max=1024),
        missing=None,
    )


@view_config(context=Yasso, name='authorize', permission='use_oauth',
        template='templates/authorize.pt')
class AuthorizeView(object):

    def __init__(self, yasso, request):
        self.yasso = yasso
        self.request = request

    def __call__(self):
        schema = AuthorizeParameters()
        try:
            params = schema.deserialize(self.request.params)
        except Invalid, e:
            return {'errors': e.messages()}

        self.client_id = params['client_id']
        self.response_types = params['response_type'].split()
        self.specified_redirect_uri = params['redirect_uri']
        self.scope = params['scope']
        self.state = params['state']

        try:
            app = self.yasso.users.get(self.client_id)
            if app is None:
                raise ValueError("Invalid client_id: %s" % self.client_id)
            self.app = app

            redirect_uri = self.specified_redirect_uri
            if not redirect_uri:
                redirect_uri = app.default_redirect_uri
            self.redirect_uri = redirect_uri
            self.check_redirect_uri()

            self.app_user = self.prepare_app_user()
            return self.finish()

        except ValueError, e:
            return {'errors': [e]}

    def prepare_app_user(self):
        userid = unicode(authenticated_userid(self.request))
        users = self.yasso.users
        user = users.get(userid)
        if user is None:
            users[userid] = user = User(users, userid)
        key = (self.app.appid, userid)
        app_users = self.yasso.app_users
        app_user = app_users.get(key)
        if app_user is None:
            app_users[key] = app_user = AppUser(*key)
        return app_user

    def finish(self):
        """Link the current profile to the app and redirect to the app."""
        query_data = {}
        fragment_data = {}
        if 'code' in self.response_types:
            # Authorization code grant: generate and return a code
            # that can be exchanged by the client for an access token.
            query_data['code'] = self.add_code()
        if 'token' in self.response_types:
            # Implicit grant: generate and return an access token
            # in the fragment component.
            fragment_data['access_token'] = self.add_token()
            fragment_data['token_type'] = 'bearer'
            fragment_data['scope'] = ' '.join(
                sorted(self.requested_permissions))
        uri = self.mix_redirect_uri(query_data, fragment_data)
        return self.redirect_response(uri)

    def add_code(self):
        # Note: include self.specified_redirect_uri in the code, so that
        # the token endpoint can check it.
        raise NotImplementedError()

    def add_token(self):
        raise NotImplementedError()

    def check_redirect_uri(self):
        if not self.redirect_uri:
            if 'token' in self.response_types:
                raise ValueError("A redirect_uri is required")
            else:
                return

        expr = self.app.redirect_uri_expr
        if expr:
            if not hasattr(expr, 'match'):
                expr = re.compile(expr)
            if expr.match(self.redirect_uri) is None:
                raise ValueError(
                    "Mismatched redirect_uri: %s" % self.redirect_uri)
        elif 'token' in self.response_types:
            raise ValueError("The token response type "
                "requires a configured redirect_uri_expr.")

        if urlsplit(self.redirect_uri).fragment:
            raise ValueError(
                "The redirect_uri must not have a fragment identifier.")

    def mix_redirect_uri(self, query_data, fragment_data):
        """Mix data into a redirect URI and return it."""
        scheme, netloc, path, query, _old_fragment = urlsplit(
            self.redirect_uri)
        fragment = ''
        if query_data:
            # Mix query_data into the query string.
            if self.state is not None:
                d = {'state': self.state}
                d.update(query_data)
                query_data = d
            q = parse_qsl(query, keep_blank_values=True)
            q = [(name, value) for (name, value) in q
                    if name not in query_data]
            q.extend(sorted(query_data.iteritems()))
            query = urlencode(q)
        if fragment_data:
            # Add fragment_data to the fragment.
            if self.state is not None:
                d = {'state': self.state}
                d.update(fragment_data)
                fragment_data = d
            fragment = urlencode(sorted(fragment_data.items()))
        return urlunsplit((scheme, netloc, path, query, fragment))

    def redirect_response(self, uri):
        """Redirect with support for fragment identifiers"""
        if '<' in uri or '>' in uri or '"' in uri:
            # URIs must never have these characters.  They
            # would lead to XSS vulnerabilities.
            raise ValueError("Invalid URI: %s" % uri)

        headers = {'Cache-Control': 'no-cache'}
        if not '#' in uri:
            return HTTPFound(location=uri, headers=headers)
        else:
            # The URI has a fragment idenfier, so use the JS + link method
            # to redirect.
            response = render_to_response('templates/redirect.pt', {
                # Don't escape the URI because it will be embedded in a script.
                'uri': Markup(uri),
            })
            response.headers.update(headers)
            return response

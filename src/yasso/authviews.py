
from colander import Invalid
from markupsafe import Markup
from pyramid.encode import urlencode
from pyramid.httpexceptions import HTTPForbidden
from pyramid.httpexceptions import HTTPFound
from pyramid.httpexceptions import HTTPUnauthorized
from pyramid.renderers import render_to_response
from pyramid.security import authenticated_userid
from pyramid.traversal import find_interface
from randenc.enc import DecryptionError
from urlparse import parse_qsl
from urlparse import urlsplit
from urlparse import urlunsplit
from yasso.models import AuthorizationServer
import colander
import time


class AuthorizeParameters(colander.MappingSchema):
    """Parameters for the authorize endpoint.

    Based on OAuth 2 sections 4.1.1 and 4.2.1.
    """
    client_id = colander.SchemaNode(
        colander.String(),
        validator=colander.Length(min=1, max=1024),
    )
    response_type = colander.SchemaNode(
        colander.String(),
        validator=colander.Length(min=1, max=1024),
    )
    redirect_uri = colander.SchemaNode(
        colander.String(),
        validator=colander.Length(min=0, max=1024),
        missing='',
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


# This view is registered in main.py.
class AuthorizeView(object):

    def __init__(self, context, request):
        self.context = context
        self.request = request
        self.authz = find_interface(context, AuthorizationServer)

    def __call__(self):
        if authenticated_userid(self.request) is None:
            return {'errors': ["You are not authenticated."]}

        schema = AuthorizeParameters()
        try:
            params = schema.deserialize(self.request.params)
        except Invalid, e:
            errors = []
            for field, message in sorted(e.asdict().items()):
                errors.append("{0}: {1}".format(field, message))
            return {'errors': errors}

        self.client_id = params['client_id']
        self.response_types = params['response_type'].split()
        self.specified_redirect_uri = params['redirect_uri']
        self.scope = params['scope']
        self.state = params['state']

        try:
            client = self.authz.clients.get(self.client_id)
            if client is None:
                raise ValueError("Invalid client_id: %s" % self.client_id)
            self.client = client

            redirect_uri = self.specified_redirect_uri
            if not redirect_uri:
                redirect_uri = client.default_redirect_uri
                if not redirect_uri:
                    raise ValueError("A redirect_uri is required.")
            self.redirect_uri = redirect_uri
            self.check_redirect_uri()

            return self.redirect()

        except ValueError, e:
            return {'errors': [e]}

    def redirect(self):
        """Prepare an auth code or token, then redirect."""
        query_data = {}
        fragment_data = {}
        if 'code' in self.response_types:
            # Authorization code grant: generate and return a code
            # that can be exchanged by the client for an access token.
            query_data['code'] = self.make_code()
        if 'token' in self.response_types:
            # Implicit grant: generate and return an access token
            # in the fragment component.
            fragment_data['access_token'] = self.make_token()
            fragment_data['token_type'] = 'bearer'
            fragment_data['scope'] = ''
        uri = self.expand_redirect_uri(query_data, fragment_data)
        return self.redirect_response(uri)

    def make_code(self):
        now = int(time.time())
        userid = authenticated_userid(self.request)
        uri = self.specified_redirect_uri
        params = ['c', now, self.client_id, userid, uri]
        return self.authz.encrypt(params)

    def make_token(self):
        now = int(time.time())
        userid = authenticated_userid(self.request)
        params = ['t', now, self.client_id, userid]
        return self.authz.encrypt(params)

    def check_redirect_uri(self):
        if not self.redirect_uri:
            if 'token' in self.response_types:
                raise ValueError("A redirect_uri is required")
            else:
                return

        expr = self.client.redirect_uri_expr
        if expr is not None:
            if expr.match(self.redirect_uri) is None:
                raise ValueError(
                    "Mismatched redirect_uri: %s" % self.redirect_uri)
        elif 'token' in self.response_types:
            raise ValueError("The token response type "
                "requires a configured redirect_uri_expr.")

        if urlsplit(self.redirect_uri).fragment:
            raise ValueError(
                "The redirect_uri must not have a fragment identifier.")

    def expand_redirect_uri(self, query_data, fragment_data):
        """Expand a redirect URI with data and return the new URI."""
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


class TokenEndpointError(Exception):
    def __init__(self, error, description):
        self.error = error
        self.description = description


# This view is registered in main.py.
def token_view(context, request):
    """Convert an OAuth authorization code to an access token."""
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
                "The given code is not an authorization code.")
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
        return {
            'access_token': token,
            'token_type': 'bearer',
            'scope': '',
        }

    except TokenEndpointError, e:
        request.response.status = '400 Bad Request'
        return {
            'error': e.error,
            'error_description': e.description,
        }


# This view is registered in main.py.
def basic_forbidden(request):
    realm = request.registry.settings.get('realm', request.host)
    auth_header = 'Basic realm="{0}"'.format(realm)
    headers = {'WWW-Authenticate': auth_header}
    if authenticated_userid(request) is not None:
        return HTTPForbidden(headers=headers)
    else:
        return HTTPUnauthorized(headers=headers)


# This view is registered in main.py.
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

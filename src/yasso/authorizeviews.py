
"""Views for the authorize application."""

from colander import Invalid
from markupsafe import Markup
from pyramid.encode import urlencode
from pyramid.httpexceptions import HTTPForbidden
from pyramid.httpexceptions import HTTPFound
from pyramid.httpexceptions import HTTPUnauthorized
from pyramid.renderers import render_to_response
from pyramid.security import authenticated_userid
from pyramid.traversal import find_interface
from pyramid.view import forbidden_view_config
from pyramid.view import view_config
from urlparse import parse_qsl
from urlparse import urlsplit
from urlparse import urlunsplit
from yasso.models import AuthorizationServer
from yasso.models import AuthorizeEndpoint
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


@view_config(context=AuthorizeEndpoint, permission='authorize',
        renderer='templates/authorize.pt')
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
            duration = self.authz.randenc.duration
            fragment_data.update({
                'access_token': self.make_token(),
                'token_type': 'bearer',
                'expires_in': duration,
                'scope': '',
            })
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
        if expr:
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


@forbidden_view_config()
def basic_forbidden(request):
    realm = request.registry.settings.get('realm', request.host)
    auth_header = 'Basic realm="{0}"'.format(realm)
    headers = {'WWW-Authenticate': auth_header}
    if authenticated_userid(request) is not None:
        return HTTPForbidden(headers=headers)
    else:
        return HTTPUnauthorized(headers=headers)


@view_config(context=AuthorizationServer, renderer='string')
def default_view(request):
    return "This is a single sign-on server."

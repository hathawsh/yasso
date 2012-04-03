
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.config import Configurator
from pyramid_who.whov2 import WhoV2AuthenticationPolicy
from yasso.authviews import AuthorizeView
from yasso.authviews import basic_forbidden
from yasso.authviews import bearer_forbidden
from yasso.authviews import token_view
from yasso.models import AuthorizationServer
from yasso.models import AuthorizeEndpoint
from yasso.models import TokenEndpoint
from yasso.policy import BearerAuthenticationPolicy
from yasso.policy import ClientAuthenticationPolicy
import re


def make_root_factory(global_config, settings):
    yasso_config = settings.get('yasso_config_file')
    if yasso_config is None:
        yasso_config = global_config['yasso_config_file']
    root = AuthorizationServer(yasso_config)
    return lambda request: root


def authorize_app(global_config, root_factory=None, **settings):
    """User-visible app."""
    if root_factory is None:
        root_factory = make_root_factory(global_config, settings)
    config = Configurator(
        root_factory=root_factory,
        settings=settings,
        authentication_policy=WhoV2AuthenticationPolicy(
            settings['who_config_file'],
            settings['who_identifier_id'],
        ),
        authorization_policy=ACLAuthorizationPolicy(),
    )
    config.add_view(
        AuthorizeView,
        context=AuthorizeEndpoint,
        permission='use_oauth',
        renderer='templates/authorize.pt',
    )
    config.add_forbidden_view(basic_forbidden)
    return config.make_wsgi_app()


def token_app(global_config, root_factory=None, **settings):
    """App for clients only. Turns auth codes into access tokens."""
    if root_factory is None:
        root_factory = make_root_factory(global_config, settings)
    config = Configurator(
        root_factory=root_factory,
        settings=settings,
        authentication_policy=ClientAuthenticationPolicy(root_factory),
        authorization_policy=ACLAuthorizationPolicy(),
    )
    config.add_view(
        token_view,
        context=TokenEndpoint,
        permission='get_token',
        renderer='json',
    )
    config.add_forbidden_view(basic_forbidden)
    return config.make_wsgi_app()


def resource_app(global_config, root_factory=None, **settings):
    """App for clients that have an access token."""
    if root_factory is None:
        root_factory = make_root_factory(global_config, settings)
    config = Configurator(
        root_factory=root_factory,
        settings=settings,
        authentication_policy=BearerAuthenticationPolicy(root_factory),
        authorization_policy=ACLAuthorizationPolicy(),
    )
    config.add_static_view('yasso-static', 'static', cache_max_age=3600)
    config.add_forbidden_view(bearer_forbidden)
    config.scan('yasso.views')
    return config.make_wsgi_app()


class CompositeApp(object):
    """Combine the 3 apps into one.

    /authorize -> authorize_app
    /token -> token_app
    / -> resource_app
    """

    authorize_re = re.compile(r'^/?authorize(/|$)')
    token_re = re.compile(r'^/?token(/|$)')

    def __init__(self, global_config, **settings):
        self.root_factory = make_root_factory(global_config, settings)
        self.authorize_app = authorize_app(
            global_config, root_factory=self.root_factory, **settings)
        self.token_app = token_app(
            global_config, root_factory=self.root_factory, **settings)
        self.resource_app = resource_app(
            global_config, root_factory=self.root_factory, **settings)

    def __call__(self, environ, start_response):
        path = environ['PATH_INFO']
        if self.authorize_re.match(path) is not None:
            app = self.authorize_app
        elif self.token_re.match(path) is not None:
            app = self.token_app
        else:
            app = self.resource_app
        return app(environ, start_response)

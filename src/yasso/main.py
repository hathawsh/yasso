
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.config import Configurator
from pyramid_who.whov2 import WhoV2AuthenticationPolicy
from yasso import authorizeviews
from yasso import resourceviews
from yasso import tokenviews
from yasso.models import AuthorizationServer
from yasso.policy import BearerAuthenticationPolicy
from yasso.policy import ClientAuthenticationPolicy
import re


def make_root_factory(global_config, settings):
    root = AuthorizationServer(settings)
    return lambda request: root


def authorize_app(global_config, root_factory=None, **settings):
    """User-visible authorization app.
    """
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
    config.add_static_view('yasso-static', 'static', cache_max_age=3600)
    config.scan(authorizeviews)
    return config.make_wsgi_app()


def token_app(global_config, root_factory=None, **settings):
    """App for clients to turn auth codes into access tokens.
    """
    if root_factory is None:
        root_factory = make_root_factory(global_config, settings)
    config = Configurator(
        root_factory=root_factory,
        settings=settings,
        authentication_policy=ClientAuthenticationPolicy(root_factory),
        authorization_policy=ACLAuthorizationPolicy(),
    )
    config.scan(tokenviews)
    return config.make_wsgi_app()


def resource_app(global_config, root_factory=None, **settings):
    """App for clients that have an access token.
    """
    if root_factory is None:
        root_factory = make_root_factory(global_config, settings)
    config = Configurator(
        root_factory=root_factory,
        settings=settings,
        authentication_policy=BearerAuthenticationPolicy(root_factory),
        authorization_policy=ACLAuthorizationPolicy(),
    )
    config.scan(resourceviews)
    return config.make_wsgi_app()


class CompositeApp(object):
    """Combine the 3 apps into one.

    /resource -> resource_app
    /token -> token_app
    / -> authorize_app
    """

    token_re = re.compile(r'^/?token(/|$)')
    resource_re = re.compile(r'^/?resource(/|$)')

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
        if self.resource_re.match(path) is not None:
            app = self.resource_app
        elif self.token_re.match(path) is not None:
            app = self.token_app
        else:
            app = self.authorize_app
        return app(environ, start_response)

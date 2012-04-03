
from pyramid.authentication import RepozeWho1AuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.config import Configurator
from yasso.models import AuthorizationServer
from yasso.policy import BearerAuthenticationPolicy
from yasso.policy import ClientAuthenticationPolicy
from yasso.views import AuthorizeView
from yasso.views import token_view
from yasso.views import token_forbidden_view


def make_root_factory(global_config, settings):
    yasso_config = settings.get('yasso_config')
    if yasso_config is None:
        yasso_config = global_config['yasso_config']
    root = AuthorizationServer(yasso_config)
    return lambda request: root


def authorize_app(global_config, **settings):
    """User-visible app."""
    root_factory = make_root_factory(global_config, settings)
    config = Configurator(
        root_factory=root_factory,
        settings=settings,
        authentication_policy=RepozeWho1AuthenticationPolicy(),
        authorization_policy=ACLAuthorizationPolicy(),
    )
    config.add_static_view('yasso-static', 'static', cache_max_age=3600)
    config.add_view(
        AuthorizeView,
        context=AuthorizationServer,
        name='authorize',
        permission='use_oauth',
        template='templates/authorize.pt',
    )
    return config.make_wsgi_app()


def token_app(global_config, **settings):
    """App for clients (servers) only. Turns auth codes into access tokens."""
    root_factory = make_root_factory(global_config, settings)
    config = Configurator(
        root_factory=root_factory,
        settings=settings,
        authentication_policy=ClientAuthenticationPolicy(root_factory),
        authorization_policy=ACLAuthorizationPolicy(),
    )
    config.add_view(
        token_view,
        context=AuthorizationServer,
        name='token',
        permission='get_token',
    )
    config.add_forbidden_view(token_forbidden_view)
    return config.make_wsgi_app()


def resource_app(global_config, **settings):
    """App for clients that have an access token."""
    root_factory = make_root_factory(global_config, settings)
    config = Configurator(
        root_factory=root_factory,
        settings=settings,
        authentication_policy=BearerAuthenticationPolicy(root_factory),
        authorization_policy=ACLAuthorizationPolicy(),
    )
    config.scan('yasso.resourceviews')
    return config.make_wsgi_app()

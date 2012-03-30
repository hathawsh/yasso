
from pyramid.authentication import SessionAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.config import Configurator
from pyramid_zodbconn import get_connection
from yasso.models import appmaker


def root_factory(request):
    conn = get_connection(request)
    return appmaker(conn.root())


def get_groups_for_user(userid, request):
    yasso = root_factory(request)
    user = yasso.users.get(userid)
    if user is not None:
        return user.groups
    else:
        return None


def main(global_config, **settings):
    """This function returns a Pyramid WSGI application.
    """
    config = Configurator(
        root_factory=root_factory,
        settings=settings,
        authentication_policy=SessionAuthenticationPolicy(
            callback=get_groups_for_user,
        ),
        authorization_policy=ACLAuthorizationPolicy(),
    )
    config.add_static_view('yasso-static', 'static', cache_max_age=3600)
    config.add_static_view('deform-static', 'deform:static')
    config.scan()
    return config.make_wsgi_app()


from BTrees.OOBTree import OOBTree  # @UnresolvedImport
from BTrees.OOBTree import OOSet  # @UnresolvedImport
from BTrees.OOBTree import OOTreeSet  # @UnresolvedImport
from persistent import Persistent
from persistent.mapping import PersistentMapping
from pyramid.security import Allow
from pyramid.security import Authenticated
from pyramid.security import DENY_ALL
from pyramid.traversal import find_interface


class User(Persistent):
    """A user that can sign in to Yasso.

    Note that users may sign in using mechanisms other than login/password,
    so pwhash and logins may be empty even for legitimate users.
    """

    __acl__ = (
        (Allow, 'group.ssoadmin', 'edit'),
        DENY_ALL,
    )

    def __init__(self, parent, userid, title, groups=(), pwhash=None):
        assert isinstance(userid, basestring)
        self.__parent__ = parent
        self.userid = userid
        self.title = title
        self.groups = tuple(groups)
        self.pwhash = pwhash
        self.logins = ()
        self.appids = OOSet()

    @property
    def __name__(self):  # @ReservedAssignment
        return self.userid

    @property
    def apps(self):
        """Get the list of apps the user is connected to."""
        yasso = find_yasso(self)
        res = []
        for appid in self.appids:
            app = yasso.apps.get(appid)
            if app is not None:
                res.append(app)
        res.sort(key=lambda app: (app.title.lower(), app.title, app.appid))
        return res

    def __repr__(self):
        return 'userid={0}, title={1}, logins={2}, groups={3}'.format(
            repr(self.userid), repr(self.title), repr(self.logins),
            repr(self.groups))


class App(Persistent):
    """An application that can receive user tokens"""

    __acl__ = (
        (Allow, 'group.ssoadmin', 'edit'),
        DENY_ALL,
    )

    def __init__(self, parent, appid, title, url, redirect_uri):
        assert isinstance(appid, basestring)
        self.__parent__ = parent
        self.appid = appid
        self.title = title
        self.url = url
        self.redirect_uri = redirect_uri
        self.userids = OOTreeSet()

    @property
    def __name__(self):  # @ReservedAssignment
        return self.appid


class AppUser(Persistent):
    """An application's properties for a user."""

    def __init__(self, appid, userid):
        assert isinstance(userid, basestring)
        assert isinstance(appid, basestring)
        self.appid = appid
        self.userid = userid
        self.code_secret = None
        self.token_secret = None
        self.properties = PersistentMapping()


class Tree(OOBTree):

    __acl__ = (
        (Allow, 'group.ssoadmin', 'add'),
        (Allow, 'group.ssoadmin', 'remove'),
        DENY_ALL,
    )

    def __init__(self, parent, name):
        super(Tree, self).__init__()
        self.__parent__ = parent
        self.__name__ = name


class UserTree(Tree):
    pass


class AppTree(Tree):
    pass


class Yasso(Persistent):

    __parent__ = None
    __name__ = None  # @ReservedAssignment

    __acl__ = (
        (Allow, Authenticated, 'use_oauth'),
        (Allow, 'group.ssoadmin', 'configure'),
        DENY_ALL,
    )

    def __init__(self):
        self.users = UserTree(self, u'users')  # {userid -> User}
        self.apps = AppTree(self, u'apps')     # {appid -> App}
        # app_users contains {(appid, userid) -> AppUser}
        self.app_users = OOBTree()
        self.logins = OOBTree()  # {login -> userid}
        self.title = u'Yet Another Single Sign-On'

    def __getitem__(self, name):
        if name == u'users':
            return self.users
        elif name == u'apps':
            return self.apps
        else:
            raise KeyError(name)

    def add_user(self, user):
        userid = user.userid
        if not userid:
            raise ValueError("Userid must not be empty")
        if userid in self.users:
            raise KeyError(userid)
        for login in user.logins:
            if login in self.logins:
                raise KeyError(login)
        self.users[userid] = user
        for login in user.logins:
            self.logins[login] = userid

    def change_logins(self, user, new_logins):
        to_add = set(new_logins).difference(set(user.logins))
        for login in to_add:
            if login in self.logins:
                raise KeyError(login)
        for login in to_add:
            self.logins[login] = user.userid
        to_remove = set(user.logins).difference(set(new_logins))
        for login in to_remove:
            if login in self.logins:
                del self.logins[login]
        user.logins = tuple(new_logins)


def find_yasso(context):
    return find_interface(context, Yasso)


def appmaker(zodb_root):
    if not 'yasso' in zodb_root:
        yasso = Yasso()
        zodb_root['yasso'] = yasso
        import transaction
        transaction.commit()
    return zodb_root['yasso']

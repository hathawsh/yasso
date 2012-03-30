
from BTrees.OOBTree import OOBTree  # @UnresolvedImport
from BTrees.OOBTree import OOSet  # @UnresolvedImport
from BTrees.OOBTree import OOTreeSet  # @UnresolvedImport
from persistent import Persistent
from persistent.mapping import PersistentMapping
from pyramid.security import Allow
from pyramid.security import DENY_ALL
from pyramid.security import Authenticated


class User(Persistent):

    __acl__ = (
        (Allow, 'admin', 'edit'),
        DENY_ALL,
    )

    def __init__(self, parent, userid):
        assert isinstance(userid, basestring)
        self.__parent__ = parent
        self.userid = userid
        self.properties = PersistentMapping()
        self.appids = OOSet()

    @property
    def __name__(self):  # @ReservedAssignment
        return self.userid


class App(Persistent):

    __acl__ = (
        (Allow, 'admin', 'edit'),
        DENY_ALL,
    )

    def __init__(self, parent, appid):
        assert isinstance(appid, basestring)
        self.__parent__ = parent
        self.appid = appid
        self.properties = PersistentMapping()
        self.userids = OOTreeSet()

    @property
    def __name__(self):  # @ReservedAssignment
        return self.appid


class AppUser(Persistent):

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
        (Allow, 'admin', 'add'),
        (Allow, 'admin', 'remove'),
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
        (Allow, 'admin', 'configure'),
        DENY_ALL,
    )

    def __init__(self):
        self.users = UserTree(self, u'users')  # {userid -> User}
        self.apps = AppTree(self, u'apps')     # {appid -> App}
        # app_users contains {(appid, userid) -> AppUser}
        self.app_users = OOBTree()
        self.title = u'Yet Another Single Sign-On'

    def __getitem__(self, name):
        if name == u'users':
            return self.users
        elif name == u'apps':
            return self.apps
        else:
            raise KeyError(name)


def appmaker(zodb_root):
    if not 'yasso' in zodb_root:
        yasso = Yasso()
        zodb_root['yasso'] = yasso
        import transaction
        transaction.commit()
    return zodb_root['yasso']

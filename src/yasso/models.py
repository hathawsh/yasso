
from BTrees.OOBTree import OOBTree  # @UnresolvedImport
from BTrees.OOBTree import OOSet  # @UnresolvedImport
from BTrees.OOBTree import OOTreeSet  # @UnresolvedImport
from persistent import Persistent
from persistent.mapping import PersistentMapping
from pyramid.security import Allow
from pyramid.security import Authenticated
from pyramid.security import DENY_ALL
from pyramid.traversal import find_interface
import datetime
import os


class User(Persistent):
    """A user that can sign in to Yasso.

    Note that users may sign in using mechanisms other than login/password,
    so pwhash and logins may be empty even for legitimate users.
    """

    __acl__ = (
        (Allow, 'group.ssoadmin', 'edit'),
        DENY_ALL,
    )

    def __init__(self, parent, userid, title=None, groups=(), pwhash=None):
        assert isinstance(userid, basestring)
        self.__parent__ = parent
        self.userid = userid
        if title is None:
            title = userid
        self.title = title
        self.groups = tuple(groups)
        self.pwhash = pwhash
        self.logins = ()
        self.clientids = OOSet()

    @property
    def __name__(self):  # @ReservedAssignment
        return self.userid

    @property
    def clients(self):
        """Get the list of clients the user is connected to."""
        yasso = find_yasso(self)
        res = []
        for clientid in self.clientids:
            client = yasso.clients.get(clientid)
            if client is not None:
                res.append(client)
        res.sort(key=lambda client: (
            client.title.lower(), client.title, client.clientid))
        return res

    def __repr__(self):
        return 'userid={0}, title={1}, logins={2}, groups={3}'.format(
            repr(self.userid), repr(self.title), repr(self.logins),
            repr(self.groups))


class Client(Persistent):
    """A web site that accepts credentials from this provider.
    """

    __acl__ = (
        (Allow, 'group.ssoadmin', 'edit'),
        DENY_ALL,
    )

    def __init__(self, parent, clientid, secret, title, url,
            redirect_uri_expr=None,
            default_redirect_uri=None):
        assert isinstance(clientid, basestring)
        self.__parent__ = parent
        self.clientid = clientid
        # The client must know the secret.
        self.secret = secret
        self.title = title
        self.url = url
        self.redirect_uri_expr = redirect_uri_expr
        self.default_redirect_uri = default_redirect_uri
        self.userids = OOTreeSet()
        now = datetime.datetime.utcnow()
        self.created = now
        # The client must not know aes_key.
        self.aes_key = os.urandom(16)

    @property
    def __name__(self):  # @ReservedAssignment
        return self.clientid


class ClientUser(Persistent):
    """A client's properties for a user."""

    def __init__(self, clientid, userid):
        assert isinstance(userid, basestring)
        assert isinstance(clientid, basestring)
        self.clientid = clientid
        self.userid = userid
        self.codes = PersistentMapping()   # {code: AuthCode}
        self.tokens = PersistentMapping()  # {token: AuthToken}
        self.properties = PersistentMapping()


class AuthCode(object):
    # Includes: created, redirect_uri.
    pass


class AuthToken(object):
    # Includes: created.
    pass


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


class ClientTree(Tree):
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
        # users contains {userid -> User}
        self.users = UserTree(self, u'users')
        # clients contains {clientid -> Client}
        self.clients = ClientTree(self, u'clients')
        # client_users contains {(appid, userid) -> AppUser}
        self.client_users = OOBTree()
        self.logins = OOBTree()  # {login -> userid}
        self.title = u'Yet Another Single Sign-On'

    def __getitem__(self, name):
        if name == u'users':
            return self.users
        elif name == u'clients':
            return self.clients
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
        """Change the logins for a user."""
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

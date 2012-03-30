
"""Yasso administration tool."""
from __future__ import print_function
from argh import ArghParser
from argh import arg
from pbkdf2 import crypt
from pyramid.paster import get_app
from pyramid.scripting import get_root
from yasso.models import User
import transaction


@arg('userid')
@arg('login')
@arg('--password', default=None, help="Set the password")
@arg('--pwhash', default=None, help="Set the password hash")
@arg('--group', help="Add the user to the specified group")
@arg('--title', help="Set the user title")
def adduser(args):
    app = get_app(args.config_uri)
    yasso, _closer = get_root(app)

    userid = args.userid
    groups = []
    if args.group:
        groups.append(args.group)

    if args.pwhash:
        pwhash = args.pwhash
    elif args.password:
        pwhash = crypt(args.password)
    else:
        pwhash = None

    if args.title:
        title = args.title
    elif args.login:
        title = args.login
    else:
        title = userid

    user = User(
        parent=yasso.users,
        userid=userid,
        title=title,
        groups=groups,
        pwhash=pwhash,
    )
    if args.login:
        user.logins = (args.login,)
    yasso.add_user(user)
    transaction.commit()


@arg('--userid', help="Find by userid")
@arg('--login', help="Find by login")
def listusers(args):
    app = get_app(args.config_uri)
    yasso, _closer = get_root(app)

    users = []
    if args.userid:
        user = yasso.users.get(args.userid)
        if user is not None:
            users.append(user)

    elif args.login:
        userid = yasso.logins.get(args.login)
        if userid:
            user = yasso.logins.get(userid)
            if user is not None:
                users.append(user)

    else:
        users.extend(yasso.users.values())
        users.sort(key=lambda user:
            (user.title.lower(), user.title, user.userid))

    for user in users:
        print(user)


@arg('userid')
@arg('--password', default=None, help="Set the password")
@arg('--pwhash', default=None, help="Set the password hash")
@arg('--title', default=None, help="Set the title")
@arg('--groups', nargs='*', help="Set the groups")
@arg('--logins', nargs='*', help="Set the logins")
def changeuser(args):
    app = get_app(args.config_uri)
    yasso, _closer = get_root(app)

    user = yasso.users[args.userid]

    if args.pwhash:
        user.pwhash = args.pwhash
    elif args.password:
        user.pwhash = crypt(args.password)

    if args.title is not None:
        user.title = args.title

    if args.groups is not None:
        user.groups = tuple(args.groups)

    if args.logins is not None:
        yasso.change_logins(args.logins)

    transaction.commit()


def main():
    parser = ArghParser()
    parser.add_argument('config_uri')
    parser.add_commands([
        adduser,
        changeuser,
        listusers,
    ])
    parser.dispatch()

if __name__ == '__main__':
    main()

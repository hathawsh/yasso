
Yasso (Yet Another Single Sign-On) is a system for building a web-based
single sign-on service using OAuth2.  It is intended to be compliant with
draft 25 of the `OAuth2 specification`_.

.. _`OAuth2 specification`: http://oauth.net/2/


Getting Started
===============

A demo configuration is included to help you get started.  Install
and run the demo configuration like this::

    $ git clone git://github.com/hathawsh/yasso.git
    $ cd yasso
    $ virtualenv --no-site-packages .
    $ bin/pip install -U zc.buildout
    $ bin/buildout
    $ bin/pserve demo.ini

The demo Yasso server will then be available at http://localhost:8510/ .
You can browse to it, but you won't see much yet.

In another shell, install and run the oauth2sample client::

    $ git clone git://github.com/hathawsh/oauth2sample.git
    $ cd oauth2sample
    $ virtualenv --no-site-packages .
    $ bin/pip install -U zc.buildout
    $ bin/buildout
    $ bin/pserve yasso-demo.ini

The sample client will then be available at http://localhost:8511/ .
Browse there.  You will be redirected to the Yasso authorize endpoint
and Yasso will request that you log in using HTTP basic authentication.
Log in with the username ``sample1``, password ``password``.  Finally, you
be redirected back to the sample OAuth2 client and you will be logged in
as sample1.  End of demo.

Assuming everything worked, that demo was short and quiet, which is
how it should be: single sign-on should be mostly invisible to users.

HTTP basic authentication is probably the first thing you'll want to replace.
To change it, create a repoze.who configuration appropriate
for your organization and use your own Pyramid configuration file
(instead of demo.ini) that points to your repoze.who configuration file.


Structure
=========

Yasso is composed of three distinct Pyramid applications.  Each has
different security policies and views, but all use the same model objects.

- The authorize application is visible to end users.  When a user
  wants to log in at a client web site, the client redirects the
  user's browser to the Yasso authorize endpoint (which is part of
  the authorize application) to let the user log in.
  Once the user logs in, Yasso redirects the browser back to the client
  web site with OAuth2 parameters; the web site calls the token
  endpoint to finish authorization.

- The token application, which provides the token endpoint, is not
  intended to be visible to users. Once a user has authenticated
  in Yasso, client web sites call the token endpoint directly
  (using a REST call) to create an access token.  An access token
  lets the client use the resource application.

- The resource application is also not intended to be visible
  to users.  Calls to the resource application require a valid
  access token in the POST parameters or HTTP headers.  The default
  resource application only allows the client web site to get
  the user ID, but you can create your own views that allow clients
  to do other things on behalf of the user.

Yasso includes a WSGI composite application that blends the three
applications together.  The composite application maps URL paths that
start with /resource to the resource application, URL paths that start
with /token to the token application, and all other URLs to the
authorize application.



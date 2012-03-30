
from setuptools import setup, find_packages
import os
import sys

requires = [
    'argh',
    'deform',
    'pbkdf2',
    'pyramid',
    'pyramid_zodbconn',
    'ZODB3',
    'transaction',
]

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.txt')).read()
CHANGES = open(os.path.join(here, 'CHANGES.txt')).read()

setup(
    name='yasso',
    version='0.1',
    description='Yet Another Single Sign-On (OAuth2 Provider)',
    long_description=README + '\n\n' +  CHANGES,
    classifiers=[
        "Programming Language :: Python",
        "Framework :: Pylons",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
    ],
    author='',
    author_email='',
    url='',
    keywords='web pylons pyramid',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    include_package_data=True,
    zip_safe=False,
    test_suite='yasso',
    install_requires=requires,
    entry_points="""
    [paste.app_factory]
    main = yasso.main:main
    [console_scripts]
    yassoctl = yasso.scripts.yassoctl:main
    """,
)

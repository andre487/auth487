import logging
import random
import sys
from functools import partial

from .common import *

try:
    import flask
except ImportError:
    logging.error('You should provide flask package to use flask auth487 lib')
    raise


def get_auth_token():
    return flask.request.cookies.get(AUTH_COOKIE_NAME)


def get_csrf_token():
    return flask.request.cookies.get(CSRF_COOKIE_NAME)


def set_csrf_token(app, resp):
    csrf_token = get_csrf_token()
    if csrf_token:
        return csrf_token

    csrf_token = hex(random.randrange(0, sys.maxsize))
    resp.set_cookie(
        CSRF_COOKIE_NAME, csrf_token,
        httponly=True, secure=not app.debug,
    )

    return csrf_token


def check_csrf_token(app, api_urls=()):
    if flask.request.method in {'GET', 'HEAD', 'OPTIONS'}:
        return

    if flask.request.path in api_urls:
        return

    expected_csrf_token = get_csrf_token()
    actual_csrf_token = flask.request.form.get(CSRF_COOKIE_NAME)

    if not expected_csrf_token or actual_csrf_token != expected_csrf_token:
        app.logger.info('CSRF: no token')
        flask.abort(flask.Response('No CSRF token', status=403))


is_authenticated = partial(is_authenticated, get_auth_token)

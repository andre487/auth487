import logging
import random
import sys
from functools import partial, wraps

from .data_handler import is_remote_addr_clean, mark_auth_mistake
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


def protected_from_brute_force(route_func):
    @wraps(route_func)
    def wrapped_route(*args, **kwargs):
        remote_addr = flask.request.remote_addr
        if not is_remote_addr_clean(remote_addr):
            logging.info('Addr %s is not clean, so ban', remote_addr)
            mark_auth_mistake(remote_addr)

            return flask.Response(
                '{"error": "Banned"}', status=403,
                headers={'Content-Type': 'application/json'},
            )

        result = route_func(*args, **kwargs)
        if result.status.startswith('403'):
            logging.info('Addr %s has auth mistake: %s', remote_addr, result.status)
            mark_auth_mistake(remote_addr)

        return result

    return wrapped_route


def require_auth(return_path=None):
    def require_auth_decorator(route_func):
        @wraps(route_func)
        def wrapped_route(*args, **kwargs):
            nonlocal return_path
            if return_path is None:
                return_path = AUTH_DOMAIN if AUTH_DOMAIN else flask.url_for('index')

            # noinspection PyArgumentList
            if has_credentials() and not is_authenticated():
                return flask.Response(
                    '{"error": "Wrong credentials"}', status=403,
                    headers={'Content-Type': 'application/json'},
                )

            # noinspection PyArgumentList
            if not is_authenticated():
                return flask.redirect(return_path, code=302)

            return route_func(*args, **kwargs)

        return wrapped_route

    return require_auth_decorator


has_credentials = partial(has_credentials, get_auth_token)
is_authenticated = partial(is_authenticated, get_auth_token)
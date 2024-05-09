import logging
import secrets
import urllib.parse
from datetime import UTC, datetime
from functools import partial, wraps

from . import common as acm, data_handler

try:
    import flask
except ImportError:
    logging.error('You should provide flask package to use flask auth487 lib')
    raise


def get_auth_token():
    return flask.request.cookies.get(acm.AUTH_COOKIE_NAME)


def get_csrf_token():
    return flask.request.cookies.get(acm.CSRF_COOKIE_NAME)


def set_csrf_token(app, resp):
    csrf_token = get_csrf_token()
    if csrf_token:
        return csrf_token

    csrf_token = secrets.token_hex(16)
    resp.set_cookie(
        acm.CSRF_COOKIE_NAME, csrf_token,
        httponly=True, secure=not app.debug, samesite='strict',
    )

    return csrf_token


def check_csrf_token(app, api_urls=()):
    if flask.request.method in {'GET', 'HEAD', 'OPTIONS'}:
        return

    if flask.request.path in api_urls:
        return

    expected_csrf_token = get_csrf_token()
    actual_csrf_token = flask.request.form.get(acm.CSRF_FIELD_NAME)

    if not expected_csrf_token or actual_csrf_token != expected_csrf_token:
        app.logger.info('CSRF: no token')
        flask.abort(flask.Response('No CSRF token', status=403))


def protected_from_brute_force(route_func):
    @wraps(route_func)
    def wrapped_route(*args, **kwargs):
        remote_addr = get_remote_addr(flask.request)
        if not data_handler.is_remote_addr_clean(remote_addr):
            logging.info('Addr %s is not clean, so ban', remote_addr)
            data_handler.mark_auth_mistake(remote_addr)

            return flask.Response(
                '{"error": "Banned"}', status=403,
                headers={'Content-Type': 'application/json'},
            )

        result = route_func(*args, **kwargs)
        if result.status.startswith('403'):
            logging.info('Addr %s has auth mistake: %s', remote_addr, result.status)
            data_handler.mark_auth_mistake(remote_addr)

        return result

    return wrapped_route


def get_remote_addr(request):
    remote_addr = request.remote_addr

    x_forwarded_for = request.environ.get('X_FORWARDED_FOR')
    x_real_ip = request.environ.get('HTTP_X_REAL_IP', x_forwarded_for)
    if x_real_ip:
        remote_addr = x_real_ip

    return remote_addr


def require_auth(auth_path=acm.AUTH_DOMAIN, return_route=None, no_redirect=False, access=()):
    if not auth_path:
        raise Exception('You should provide auth path via AUTH_DOMAIN var or via argument')

    def require_auth_decorator(route_func):
        ret_route = return_route
        if ret_route is None:
            ret_route = route_func.__name__

        @wraps(route_func)
        def wrapped_route(*args, **kwargs):
            url_root = flask.request.url_root
            if url_root.endswith('/'):
                url_root = url_root[:-1]

            return_url = urllib.parse.quote(
                url_root +
                flask.url_for(ret_route)
            )

            auth_url = (
                auth_path +
                ('&' if '?' in auth_path else '?') +
                'return-path=' +
                return_url
            )

            if not (auth_info := get_auth_info_from_token()):
                if no_redirect:
                    return flask.Response(
                        '{"error": "Auth error"}', status=403,
                        headers={'Content-Type': 'application/json'},
                    )
                return flask.redirect(auth_url, code=302)

            now = datetime.now(tz=UTC).timestamp()
            if not (issued_at := auth_info.get('iat')) or issued_at > now:
                if no_redirect:
                    return flask.Response(
                        '{"error": "Token time is invalid"}', status=401,
                        headers={'Content-Type': 'application/json'},
                    )
                return flask.redirect(auth_url, code=302)

            if not (not_before := auth_info.get('nbf')) or not_before > now:
                if no_redirect:
                    return flask.Response(
                        '{"error": "Token is too new"}', status=401,
                        headers={'Content-Type': 'application/json'},
                    )
                return flask.redirect(auth_url, code=302)

            if not (expires := auth_info.get('exp')) or expires < now:
                if no_redirect:
                    return flask.Response(
                        '{"error": "Token is expired"}', status=401,
                        headers={'Content-Type': 'application/json'},
                    )
                return flask.redirect(auth_url, code=302)

            has_access = True
            for rule in access:
                has_access = has_access and data_handler.has_access_to(auth_info, rule)
                if not has_access:
                    break

            if not has_access:
                return flask.Response(
                    '{"error": "You are not authorized for this service"}', status=401,
                    headers={'Content-Type': 'application/json'},
                )

            return route_func(*args, **kwargs)

        return wrapped_route

    return require_auth_decorator


is_authenticated = partial(acm.is_authenticated, get_auth_token)
get_auth_info_from_token = partial(acm.get_auth_info_from_token, get_auth_token)

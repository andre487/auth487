import hashlib
import json
import logging
import os
from datetime import datetime, timedelta

import flask
from lib.auth487 import flask as ath, common as acm, data_handler
from lib.auth487.common import create_auth_token, PRIVATE_KEY, PUBLIC_KEY

AUTH_INFO_FILE = os.environ.get('AUTH_INFO_FILE')

assert PRIVATE_KEY, 'You should pass existing secret via AUTH_PRIVATE_KEY_FILE environment variable'
assert PUBLIC_KEY, 'You should pass existing secret via AUTH_PUBLIC_KEY_FILE environment variable'

assert AUTH_INFO_FILE, 'You should pass auth file via AUTH_INFO_FILE environment variable'

with open(AUTH_INFO_FILE) as fp:
    AUTH_INFO_DATA = json.load(fp)

# noinspection SpellCheckingInspection
LOG_FORMAT = '%(asctime)s %(levelname)s\t%(message)s\t%(pathname)s:%(lineno)d %(funcName)s %(process)d %(threadName)s'
LOG_LEVEL = os.environ.get('LOG_LEVEL', logging.INFO)

ADDITIONAL_HEADERS = {
    'Content-Security-Policy': (
        "default-src 'none'; "
        "style-src 'self'; "
        "script-src 'self'; "
        "img-src 'self';"
    ),
    'X-Frame-Options': 'deny'
}

logging.basicConfig(format=LOG_FORMAT, level=LOG_LEVEL)

app = flask.Flask(__name__)


@app.before_request
def before_request():
    ath.check_csrf_token(app)


@app.route('/')
@ath.protected_from_brute_force
def index():
    return_path = flask.request.args.get('return-path', flask.url_for('index'))

    # noinspection PyArgumentList
    if ath.is_authenticated():
        auth_token = ath.get_auth_token()
        auth_info = acm.extract_auth_info(auth_token)
        banned_ips = data_handler.get_banned_addresses(auth_info)
        banned_ips_authorized = data_handler.has_access_to(auth_info, 'banned_ips')

        return make_template_response(
            'user-panel.html',
            return_path=return_path, banned_ips=banned_ips,
            auth_token=auth_token, auth_info=auth_info,
            banned_ips_authorized=banned_ips_authorized,
        )

    return make_template_response('auth-form.html', return_path=return_path, hide_logout=True)


@app.route('/login', methods=('POST',))
@ath.protected_from_brute_force
def login():
    login = flask.request.form.get('login')
    password = flask.request.form.get('password')
    return_path = flask.request.form.get('return-path', flask.url_for('index'))

    if not login or not password:
        return flask.Response('No auth info', status=400)

    auth_data = AUTH_INFO_DATA.get(login, {})
    expected_password_hash = auth_data.get("password")

    if not expected_password_hash:
        return flask.Response('Wrong login or password', status=403)

    hasher = hashlib.sha512()
    hasher.update(password.encode('utf-8'))
    actual_password_hash = hasher.hexdigest()

    if actual_password_hash != expected_password_hash:
        return flask.Response('Wrong login or password', status=403)

    auth_token = create_auth_token(login, auth_data, PRIVATE_KEY)
    expires = datetime.now() + timedelta(days=30)
    domain = None if app.debug else acm.AUTH_DOMAIN

    resp = flask.redirect(return_path, code=302)
    # noinspection PyTypeChecker
    resp.set_cookie(
        acm.AUTH_COOKIE_NAME, auth_token, expires=expires,
        domain=domain, httponly=True, secure=not app.debug,
    )

    return make_response(resp)


@app.route('/logout', methods=('POST',))
@ath.protected_from_brute_force
def logout():
    return_path = flask.request.form.get('return-path', flask.url_for('index'))

    auth_token = ''
    expires = datetime.now() - timedelta(days=30)
    domain = None if app.debug else acm.AUTH_DOMAIN

    resp = flask.redirect(return_path, code=302)
    # noinspection PyTypeChecker
    resp.set_cookie(
        acm.AUTH_COOKIE_NAME, auth_token, expires=expires,
        domain=domain, httponly=True, secure=not app.debug,
    )

    return make_response(resp)


@app.route('/get-public-key')
@ath.protected_from_brute_force
def get_public_key():
    return flask.Response(PUBLIC_KEY, headers={'Content-Type': 'text/plain; charset=utf-8'})


def make_template_response(template, **kwargs):
    resp = make_response()
    # noinspection PyUnresolvedReferences
    resp.response.append(flask.render_template(template, **kwargs))

    return resp


def make_json_response(data):
    str_data = json.dumps(data, indent=2, ensure_ascii=False)
    resp = flask.Response(response=str_data, headers={'Content-Type': 'application/json; charset=utf-8'})
    return make_response(resp)


def make_response(base_resp=None):
    if not base_resp:
        base_resp = flask.Response()

    for name, val in ADDITIONAL_HEADERS.items():
        base_resp.headers[name] = val

    app.jinja_env.globals['csrf_token'] = ath.set_csrf_token(app, resp=base_resp)

    return base_resp

import hashlib
import json
import os
from datetime import datetime, timedelta

import flask
from authlib.jose import jwt
from lib.auth487 import flask as ath

AUTH_INFO_FILE = os.environ.get('AUTH_INFO_FILE')

PRIVATE_KEY = ath.PRIVATE_KEY
PUBLIC_KEY = ath.PUBLIC_KEY

assert PRIVATE_KEY, 'You should pass existing secret via AUTH_PRIVATE_KEY_FILE environment variable'
assert PUBLIC_KEY, 'You should pass existing secret via AUTH_PUBLIC_KEY_FILE environment variable'

assert AUTH_INFO_FILE, 'You should pass auth file via AUTH_INFO_FILE environment variable'

with open(AUTH_INFO_FILE) as fp:
    AUTH_INFO_DATA = json.load(fp)

app = flask.Flask(__name__)


@app.before_request
def before_request():
    ath.check_csrf_token(app)


@app.route('/')
@ath.protected_from_brute_force
def index():
    return_path = flask.request.args.get('return-path', flask.url_for('index'))

    # noinspection PyArgumentList
    if ath.has_credentials() and not ath.is_authenticated():
        return flask.Response('Wrong credentials', status=403)

    # noinspection PyArgumentList
    if ath.is_authenticated():
        app.logger.info('AUTH: OK')
        return make_template_response('user-panel.html', return_path=return_path)

    app.logger.info('AUTH: need auth')
    return make_template_response('auth-form.html', return_path=return_path)


@app.route('/login', methods=('POST',))
@ath.protected_from_brute_force
def login():
    login = flask.request.form.get('login')
    password = flask.request.form.get('password')
    return_path = flask.request.form.get('return-path', flask.url_for('index'))

    if not login or not password:
        app.logger.info('LOGIN: no auth info')
        return flask.Response('No auth info', status=400)

    expected_password_hash = AUTH_INFO_DATA.get(login)

    if not expected_password_hash:
        app.logger.info('LOGIN: wrong login')
        return flask.Response('Wrong login', status=403)

    hasher = hashlib.sha512()
    hasher.update(password.encode('utf-8'))
    actual_password_hash = hasher.hexdigest()

    if actual_password_hash != expected_password_hash:
        app.logger.info('LOGIN: wrong password')
        return flask.Response('Wrong password', status=403)

    header = {'alg': 'RS256'}
    payload = {'login': login}

    auth_token = jwt.encode(header, payload, PRIVATE_KEY)
    expires = datetime.now() + timedelta(days=30)
    domain = None if app.debug else ath.AUTH_DOMAIN

    resp = flask.redirect(return_path, code=302)
    resp.set_cookie(
        ath.AUTH_COOKIE_NAME, auth_token, expires=expires,
        domain=domain, httponly=True, secure=not app.debug,
    )

    app.logger.info('LOGIN: OK')
    return make_response(resp)


@app.route('/logout', methods=('POST',))
def logout():
    return_path = flask.request.form.get('return-path', flask.url_for('index'))

    auth_token = ''
    expires = datetime.now() - timedelta(days=30)
    domain = None if app.debug else ath.AUTH_DOMAIN

    resp = flask.redirect(return_path, code=302)
    resp.set_cookie(
        ath.AUTH_COOKIE_NAME, auth_token, expires=expires,
        domain=domain, httponly=True, secure=not app.debug,
    )

    app.logger.info('LOGOUT: OK')
    return make_response(resp)


@app.route('/get-auth-info')
def get_auth_info():
    auth_token = flask.request.args.get('auth-token')
    if not auth_token:
        auth_token = ath.get_auth_token()

    if not auth_token:
        return flask.Response('No token', status=400)

    auth_info = ath.extract_auth_info(auth_token)
    return make_json_response(auth_info)


@app.route('/get-public-key')
def get_public_key():
    return flask.Response(PUBLIC_KEY, headers={'Content-Type': 'text.plain;charset=utf-8'})


@app.route('/get-token', methods=('POST',))
def get_token():
    auth_token = ath.get_auth_token()
    if not auth_token:
        app.logger.info('GET TOKEN: no token')
        return flask.Response('No token', status=403)

    return make_template_response('show-token.html', auth_token=auth_token)


def make_template_response(template, **kwargs):
    resp = make_response()
    resp.response.append(flask.render_template(template, **kwargs))

    return resp


def make_json_response(data):
    str_data = json.dumps(data, indent=2, ensure_ascii=False)
    resp = flask.Response(response=str_data, headers={'Content-Type': 'application/json;charset=utf-8'})
    return make_response(resp)


def make_response(base_resp=None):
    if not base_resp:
        base_resp = flask.Response()

    base_resp.headers['Content-Security-Policy'] = (
        "default-src 'none'; "
        "style-src 'self'; "
        "script-src 'self'; "
        "img-src 'self';"
    )
    app.jinja_env.globals['csrf_token'] = ath.set_csrf_token(app, resp=base_resp)

    return base_resp

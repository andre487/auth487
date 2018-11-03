import hashlib
import json
import random
import os
import sys
from datetime import datetime, timedelta

import flask
from authlib.specs.rfc7519 import jwt
from authlib.specs.rfc7515 import BadSignatureError

app = flask.Flask(__name__)

private_key_file = os.environ.get('AUTH_PRIVATE_KEY_FILE')
public_key_file = os.environ.get('AUTH_PUBLIC_KEY_FILE')

auth_domain = os.environ.get('AUTH_DOMAIN', 'localhost')
auth_info_file = os.environ.get('AUTH_INFO_FILE')

assert private_key_file, 'You should pass secret via AUTH_PRIVATE_KEY_FILE environment variable'
assert public_key_file, 'You should pass secret via AUTH_PUBLIC_KEY_FILE environment variable'

assert auth_info_file, 'You should pass auth file via AUTH_INFO_FILE environment variable'

with open(private_key_file) as fp:
    private_key = fp.read()

with open(public_key_file) as fp:
    public_key = fp.read()

with open(auth_info_file) as fp:
    auth_info_data = json.load(fp)


@app.before_request
def csrf_protection():
    if flask.request.method in {'GET', 'HEAD', 'OPTIONS'}:
        app.logger.warn('CSRF: wrong method')
        return

    if flask.request.path == flask.url_for('get_auth_info'):
        app.logger.info('CSRF: visit get_auth_info')
        return

    expected_csrf_token = flask.request.cookies.get('CSRF_TOKEN')
    actual_csrf_token = flask.request.form.get('CSRF_TOKEN')

    if not expected_csrf_token or actual_csrf_token != expected_csrf_token:
        app.logger.info('CSRF: no token')
        flask.abort(flask.Response('No CSRF token', status=403))


@app.route('/')
def index():
    return_path = flask.request.args.get('return-path', flask.url_for('index'))

    if is_authenticated():
        app.logger.info('AUTH: OK')
        return make_template_response('user-panel.html', return_path=return_path)

    app.logger.info('AUTH: need auth')
    return make_template_response('auth-form.html', return_path=return_path)


@app.route('/login', methods=('POST',))
def login():
    login = flask.request.form.get('login')
    password = flask.request.form.get('password')
    return_path = flask.request.form.get('return-path', flask.url_for('index'))

    if not login or not password:
        app.logger.info('LOGIN: no auth info')
        return flask.abort(flask.Response('No auth info', status=400))

    expected_password_hash = auth_info_data.get(login)

    if not expected_password_hash:
        app.logger.info('LOGIN: wrong login')
        return flask.abort(flask.Response('Wrong login', status=403))

    hasher = hashlib.sha512()
    hasher.update(password.encode('utf-8'))
    actual_password_hash = hasher.hexdigest()

    if actual_password_hash != expected_password_hash:
        app.logger.info('LOGIN: wrong password')
        return flask.abort(flask.Response('Wrong password', status=403))

    header = {'alg': 'RS256'}
    payload = {'login': login}

    auth_token = jwt.encode(header, payload, private_key)
    expires = datetime.now() + timedelta(days=30)
    domain = auth_domain if not app.debug else None

    resp = flask.redirect(return_path, code=302)
    resp.set_cookie('AUTH_TOKEN', auth_token, expires=expires, domain=domain, httponly=True, secure=not app.debug)

    app.logger.info('LOGIN: OK')
    return make_response(resp)


@app.route('/logout', methods=('POST',))
def logout():
    return_path = flask.request.form.get('return-path', flask.url_for('index'))

    auth_token = ''
    expires = datetime.now() - timedelta(days=30)
    domain = auth_domain if not app.debug else None

    resp = flask.redirect(return_path, code=302)
    resp.set_cookie('AUTH_TOKEN', auth_token, expires=expires,
        domain=domain, httponly=True, secure=not app.debug)

    app.logger.info('LOGOUT: OK')
    return make_response(resp)


@app.route('/get-auth-info', methods=('POST',))
def get_auth_info():
    auth_info = extract_auth_info(flask.request.form.get('auth-token'))
    return json.dumps(auth_info)


@app.route('/get-public-key')
def get_public_key():
    return public_key


@app.route('/get-token', methods=('POST',))
def get_token():
    auth_token = flask.request.cookies.get('AUTH_TOKEN')
    if not auth_token:
        app.logger.info('GET TOKEN: no token')
        return flask.abort(flask.Response('No token', status=400))

    return make_template_response('show-token.html', auth_token=auth_token)


def is_authenticated():
    auth_token = flask.request.cookies.get('AUTH_TOKEN')
    if not auth_token:
        return False

    auth_info = extract_auth_info(auth_token)
    return bool(auth_info)


def extract_auth_info(auth_token=None):
    if not auth_token:
        auth_token = flask.request.cookies.get('AUTH_TOKEN')

    try:
        claims = jwt.decode(auth_token, public_key)
    except BadSignatureError:
        return False

    return dict(claims)


def make_template_response(template, **kwargs):
    resp = make_response()
    resp.response.append(flask.render_template(template, **kwargs))

    return resp


def make_response(base_resp=None):
    if not base_resp:
        base_resp = flask.Response()

    csrf_token = flask.request.cookies.get('CSRF_TOKEN')
    if not csrf_token:
        csrf_token = hex(random.randrange(0, sys.maxsize))
        base_resp.set_cookie('CSRF_TOKEN', csrf_token,
            httponly=True, secure=not app.debug)

    app.jinja_env.globals['csrf_token'] = csrf_token

    return base_resp

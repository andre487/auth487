import hashlib
import json
import random
import os
import sys
from datetime import datetime, timedelta

import flask
import jwt

app = flask.Flask(__name__)

auth_secret = os.environ.get('AUTH_SECRET')
auth_domain = os.environ.get('AUTH_DOMAIN', 'localhost')
auth_info_file = os.environ.get('AUTH_INFO_FILE')

assert auth_secret, 'You should pass secret via AUTH_SECRET environment variable'
assert auth_info_file, 'You should pass auth file via AUTH_INFO_FILE environment variable'

with open(auth_info_file) as fp:
    auth_info_data = json.load(fp)


@app.before_request
def csrf_protection():
    if flask.request.method in {'GET', 'HEAD', 'OPTIONS'}:
        return

    if flask.request.path == flask.url_for('get_auth_info'):
        return

    expected_csrf_token = flask.request.cookies.get('CSRF_TOKEN')
    actual_csrf_token = flask.request.form.get('CSRF_TOKEN')

    if not expected_csrf_token or actual_csrf_token != expected_csrf_token:
        flask.abort(flask.Response('No CSRF token', status=403))


@app.route('/')
def index():
    if is_authenticated():
        return make_template_response('get-token-form.html')

    return make_template_response('auth-form.html')


@app.route('/login', methods=('POST',))
def login():
    login = flask.request.form.get('login')
    password = flask.request.form.get('password')
    return_path = flask.request.form.get('returl_path', flask.url_for('index'))

    if not login or not password:
        return flask.abort(flask.Response('No auth info', status=400))

    expected_password_hash = auth_info_data.get(login)

    if not expected_password_hash:
        return flask.abort(flask.Response('Wrong login', status=403))

    hasher = hashlib.sha512()
    hasher.update(password.encode('utf-8'))
    actual_password_hash = hasher.hexdigest()

    if actual_password_hash != expected_password_hash:
        return flask.abort(flask.Response('Wrong password', status=403))

    auth_token = jwt.encode({'login': login}, auth_secret)
    expires = datetime.now() + timedelta(days=30)
    domain = auth_domain if not app.debug else None

    resp = flask.redirect(return_path, code=302)
    resp.set_cookie('AUTH_TOKEN', auth_token, expires=expires,
                    domain=domain, httponly=True, secure=not app.debug)

    return make_response(resp)


@app.route('/get-auth-info', methods=('POST',))
def get_auth_info():
    auth_info = extract_auth_info(flask.request.form.get('auth-token'))
    return json.dumps(auth_info)


@app.route('/get-token', methods=('POST',))
def get_token():
    auth_token = flask.request.cookies.get('AUTH_TOKEN')
    if not auth_token:
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
        data = jwt.decode(auth_token, auth_secret)
    except jwt.exceptions.DecodeError as e:
        return flask.abort(flask.Response(str(e), status=403))

    return data


def make_template_response(template, **kwargs):
    resp = make_response()
    resp.response = flask.render_template(template, **kwargs)

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

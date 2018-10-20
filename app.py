import random
import os
import sys
from datetime import datetime, timedelta

import flask
import jwt

app = flask.Flask(__name__)

auth_secret = os.environ.get('AUTH_SECRET')
auth_domain = os.environ.get('AUTH_DOMAIN', 'localhost')

assert auth_secret, 'You should pass secret via AUTH_SECRET environment variable'


@app.before_request
def csrf_protection():
    if flask.request.method in {'GET', 'HEAD', 'OPTIONS'}:
        return

    expected_csrf_token = flask.request.cookies.get('CSRF_TOKEN')
    actual_csrf_token = flask.request.form.get('CSRF_TOKEN')

    if not expected_csrf_token or actual_csrf_token != expected_csrf_token:
        flask.abort(flask.Response('No CSRF token', status=403))


@app.route('/')
def index():
    return make_response(
        flask.render_template('auth-form.html')
    )


@app.route('/login', methods=('POST',))
def login():
    login = flask.request.form.get('login')
    password = flask.request.form.get('password')
    return_path = flask.request.form.get('returl_path', flask.url_for('index'))

    if not login or not password:
        return flask.abort(flask.Response('No auth info', status=400))

    auth_token = jwt.encode({'login': login}, auth_secret)
    expires = datetime.now() + timedelta(days=30)
    domain = auth_domain if not app.debug else None

    resp = flask.redirect(return_path, code=302)
    resp.set_cookie('AUTH_TOKEN', auth_token, expires=expires,
                    domain=domain, httponly=True, secure=not app.debug)

    return make_response(resp)


def make_response(content):
    resp = flask.make_response(content)

    csrf_token = flask.request.cookies.get('CSRF_TOKEN')
    if not csrf_token:
        csrf_token = hex(random.randrange(0, sys.maxsize))
        resp.set_cookie('CSRF_TOKEN', csrf_token,
                        httponly=True, secure=not app.debug)

    app.jinja_env.globals['csrf_token'] = csrf_token
    return resp

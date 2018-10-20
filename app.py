import random
import os
import sys

import flask
import jwt

app = flask.Flask(__name__)
secret = os.environ.get('AUTH_SECRET')

assert secret, 'You should pass secret via AUTH_SECRET environment variable'


@app.before_request
def csrf_protection():
    if flask.request.method in {'GET', 'HEAD', 'OPTIONS'}:
        return

    expected_csrf_token = flask.request.cookies.get('CSRF_TOKEN')
    actual_csrf_token = flask.request.form.get('CSRF_TOKEN')

    if not expected_csrf_token or actual_csrf_token != expected_csrf_token:
        flask.abort(403)


@app.route('/')
def index():
    return make_response(flask.render_template('auth-form.html'))


def make_response(content):
    resp = flask.make_response(content)

    csrf_token = flask.request.cookies.get('CSRF_TOKEN')
    if not csrf_token:
        csrf_token = hex(random.randrange(0, sys.maxsize))
        resp.set_cookie('CSRF_TOKEN', csrf_token,
                        httponly=True, secure=not app.debug)

    app.jinja_env.globals['csrf_token'] = csrf_token
    return resp

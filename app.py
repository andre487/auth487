import json
import logging.config
import os
import secrets
import sys
import urllib.parse
from datetime import datetime, timedelta

import flask
import pyotp
import pytz
import werkzeug.exceptions

import app_common
import mail
import templating
from lib.auth487 import common as acm, data_handler, flask as ath

AUTH_DOMAIN = os.getenv('AUTH_DOMAIN', '127.0.0.1')

AUTH_INFO_FILE = os.getenv('AUTH_INFO_FILE')
if not AUTH_INFO_FILE:
    raise EnvironmentError('You should pass auth file via AUTH_INFO_FILE environment variable')

PRIVATE_KEY_FILE = os.environ.get('AUTH_PRIVATE_KEY_FILE')
if not PRIVATE_KEY_FILE:
    raise EnvironmentError('You should pass private key file via AUTH_PRIVATE_KEY_FILE environment variable')

ADDITIONAL_HEADERS = {
    'X-Frame-Options': 'deny',
}

CSP_HEADER_TPL = (
    "default-src 'none'; "
    "style-src 'nonce-{nonce}'; "
    "script-src 'nonce-{nonce}'; "
    "img-src 'self';"
)

LOG_FORMAT = '%(asctime)s %(levelname)s\t%(name)s\t%(message)s\t'
LOG_LEVEL = os.environ.get('LOG_LEVEL', logging.INFO)

logging.config.dictConfig({
    'version': 1,
    'formatters': {
        'default': {
            'format': LOG_FORMAT,
        }
    },
    'handlers': {
        'wsgi': {
            'class': 'logging.StreamHandler',
            'stream': sys.stderr,
            'formatter': 'default',
        }
    },
    'root': {
        'level': LOG_LEVEL,
        'handlers': ['wsgi'],
    }
})

logging.basicConfig(level=LOG_LEVEL)

app = flask.Flask(__name__)
templating.setup_filters(app)


@app.before_request
def before_request():
    ath.check_csrf_token(app)


@app.route('/')
@ath.protected_from_brute_force
def index():
    return_path = flask.request.args.get('return-path', flask.url_for('index'))
    return_path_parts = urllib.parse.urlparse(return_path)
    if return_path_parts.netloc and not return_path_parts.netloc.endswith(AUTH_DOMAIN):
        raise werkzeug.exceptions.BadRequest('Return path is invalid')

    if ath.is_authenticated():
        auth_token = ath.get_auth_token()
        auth_data = ath.check_auth_info_from_token()
        banned_ips = data_handler.get_banned_addresses(auth_data.auth_info)
        banned_ips_authorized = data_handler.has_access_to(auth_data.auth_info, 'banned_ips')

        return make_template_response(
            'user-panel.html',
            return_path=return_path, banned_ips=banned_ips,
            auth_token=auth_token, auth_info=auth_data.auth_info,
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
        raise werkzeug.exceptions.BadRequest('No auth info')

    auth_data = get_auth_info_data().get(login)
    if not auth_data:
        raise werkzeug.exceptions.Forbidden('User is not found')

    actual_password_hash = app_common.hash_password(password)
    expected_password_hash = auth_data.get("password")
    if actual_password_hash != expected_password_hash:
        raise werkzeug.exceptions.Forbidden('Wrong password')

    auth_id = data_handler.create_second_factor_record(login, auth_data, actual_password_hash)

    headers = {}
    if acm.AUTH_DEV_MODE:
        headers['X-Auth-Id'] = auth_id

    return make_template_response(
        'totp-form.html',
        login=login, auth_id=auth_id, return_path=return_path, hide_logout=True,
        http_headers=headers
    )


@app.route('/submit-totp', methods=('POST',))
@ath.protected_from_brute_force
def submit_totp():
    login = flask.request.form.get('login')
    password = flask.request.form.get('password')
    auth_id = flask.request.form.get('auth_id')
    return_path = flask.request.form.get('return-path', flask.url_for('index'))

    if not login or not password or not auth_id:
        raise werkzeug.exceptions.BadRequest('No auth info')

    auth_data = get_auth_info_data().get(login)
    if not auth_data:
        raise werkzeug.exceptions.Forbidden('User is not found')

    sf_record = data_handler.get_second_factor_record(login, auth_id)
    if not sf_record:
        raise werkzeug.exceptions.BadRequest('No auth info')

    data_handler.remove_second_factor_record(login, auth_id)

    expected_password_hash = auth_data.get("password")
    if not expected_password_hash:
        raise werkzeug.exceptions.Forbidden('Wrong login or password')

    if not pyotp.TOTP(auth_data['totp_secret']).verify(password):
        raise werkzeug.exceptions.Forbidden('Wrong OTP')

    if sf_record['password_hash'] != expected_password_hash:
        raise werkzeug.exceptions.Forbidden('Wrong password')

    resp = flask.redirect(return_path, code=302)
    mail.send_new_login_notification(flask.request, resp)

    auth_token = acm.create_auth_token(login, auth_data, get_private_key())
    exp_days = auth_data.get('expiration_days', 1)
    expires = datetime.now(tz=pytz.utc) + timedelta(days=exp_days)
    domain = None if app.debug else AUTH_DOMAIN

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
    domain = None if app.debug else AUTH_DOMAIN

    resp = flask.redirect(return_path, code=302)
    resp.set_cookie(
        acm.AUTH_COOKIE_NAME, auth_token, expires=expires,
        domain=domain, httponly=True, secure=not app.debug,
    )

    return make_response(resp)


@app.route('/get-public-key')
def get_public_key():
    return flask.Response(acm.get_public_key(), headers={'Content-Type': 'text/plain; charset=utf-8'})


@app.route('/robots.txt')
def robots_txt():
    return flask.Response(
        response=(
            'User-Agent: *\n'
            'Disallow: /'
        ),
        headers={'Content-Type': 'text/plain; charset=utf-8'}
    )


@app.errorhandler(werkzeug.exceptions.HTTPException)
def error_page_http(e: werkzeug.exceptions.HTTPException):
    err_msg = f'{e.code} {type(e).__name__}'
    return make_template_response(
        'error.html',
        page_title=err_msg,
        error_type=err_msg,
        error_description=e.description,
        hide_logout=True,
        code=e.code,
    )


@app.errorhandler(Exception)
def error_page_exc(e: Exception):
    err_code = 500
    err_msg = f'{err_code} Internal Server Error'
    return make_template_response(
        'error.html',
        page_title=err_msg,
        error_type=err_msg,
        error_description=str(e),
        hide_logout=True,
        code=err_code,
    )


def make_template_response(template, **kwargs):
    code = kwargs.pop('code', 200)
    resp = make_response(code=code, **kwargs)

    if 'base_resp' in kwargs:
        del kwargs['base_resp']

    if 'http_headers' in kwargs:
        del kwargs['http_headers']

    # noinspection PyUnresolvedReferences
    resp.response.append(flask.render_template(template, **kwargs))

    return resp


def make_json_response(data, **kwargs):
    str_data = json.dumps(data, indent=2, ensure_ascii=False)
    resp = flask.Response(response=str_data, headers={'Content-Type': 'application/json; charset=utf-8'})
    return make_response(resp, **kwargs)


def make_response(base_resp=None, http_headers=None, code=200, **_):
    if not base_resp:
        base_resp = flask.Response(status=code)

    for name, val in ADDITIONAL_HEADERS.items():
        base_resp.headers[name] = val

    if http_headers is None:
        http_headers = {}

    for name, val in http_headers.items():
        base_resp.headers[name] = val

    nonce = secrets.token_hex(8)
    base_resp.headers['Content-Security-Policy'] = CSP_HEADER_TPL.format(nonce=nonce)

    app.jinja_env.globals.update(
        csrf_field_name=acm.CSRF_FIELD_NAME,
        csrf_token=ath.set_csrf_token(app, resp=base_resp),
        csp_nonce=nonce,
    )

    return base_resp


def get_private_key():
    with open(PRIVATE_KEY_FILE) as fp:
        return fp.read()


def get_auth_info_data():
    with open(AUTH_INFO_FILE) as fp:
        return json.load(fp)

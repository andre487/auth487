import hashlib
import json
import logging
import os
import flask
import mail
import pyotp
import templating
from datetime import datetime, timedelta
from lib.auth487 import flask as ath, common as acm, data_handler
from lib.auth487.common import create_auth_token, PRIVATE_KEY, PUBLIC_KEY

AUTH_INFO_FILE = os.getenv('AUTH_INFO_FILE')

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
templating.setup_filters(app)


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

    auth_data = AUTH_INFO_DATA.get(login)
    if not auth_data:
        return flask.Response('User is not found', status=403)

    actual_password_hash = hashlib.sha512(password.encode('utf-8')).hexdigest()
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
        return flask.Response('No auth info', status=400)

    auth_data = AUTH_INFO_DATA.get(login)
    if not auth_data:
        return flask.Response('User is not found', status=403)

    sf_record = data_handler.get_second_factor_record(login, auth_id)
    if not sf_record:
        return flask.Response('No auth info', status=400)

    data_handler.remove_second_factor_record(login, auth_id)

    expected_password_hash = auth_data.get("password")
    if not expected_password_hash:
        return flask.Response('Wrong login or password', status=403)

    if not pyotp.TOTP(auth_data['totp_secret']).verify(password):
        return flask.Response('Wrong OTP', status=403)

    if sf_record['password_hash'] != expected_password_hash:
        return flask.Response('Wrong login or password', status=403)

    resp = flask.redirect(return_path, code=302)
    mail.send_new_login_notification(flask.request, resp)

    auth_token = create_auth_token(login, auth_data, PRIVATE_KEY)
    expires = datetime.now() + timedelta(days=30)
    domain = None if app.debug else acm.AUTH_DOMAIN

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


@app.route('/robots.txt')
def robots_txt():
    return flask.Response(
        response=(
            'User-Agent: *\n'
            'Disallow: /'
        ),
        headers={'Content-Type': 'text/plain; charset=utf-8'}
    )


def make_template_response(template, **kwargs):
    resp = make_response(**kwargs)

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


def make_response(base_resp=None, http_headers=None, **_):
    if not base_resp:
        base_resp = flask.Response()

    for name, val in ADDITIONAL_HEADERS.items():
        base_resp.headers[name] = val

    if http_headers is None:
        http_headers = {}

    for name, val in http_headers.items():
        base_resp.headers[name] = val

    app.jinja_env.globals.update(
        csrf_field_name=acm.CSRF_FIELD_NAME,
        csrf_token=ath.set_csrf_token(app, resp=base_resp),
    )

    return base_resp

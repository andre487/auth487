import json
import os
from urllib import parse as url_parse

import pyotp
import requests

from cli_tasks import common
from lib.auth487 import common as acm

APP_PORT = int(os.getenv('APP_PORT', 8080))

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), 'test_data')
AUTH_INFO_FILE = os.path.join(TEST_DATA_DIR, 'test-auth-info.json')
PRIVATE_KEY_FILE = os.path.join(TEST_DATA_DIR, 'auth_keys', 'auth_key.pem')

with open(AUTH_INFO_FILE) as fp:
    AUTH_INFO_DATA = json.load(fp)

with open(PRIVATE_KEY_FILE) as fp:
    PRIVATE_KEY = fp.read()


def generate_auth_token(login='test'):
    auth_data = AUTH_INFO_DATA[login]
    return acm.create_auth_token(login, auth_data, PRIVATE_KEY)


def make_app_request(handler, method='GET', data=None, headers=None, cookies=None, set_token=True):
    if cookies is None:
        cookies = {}

    auth_token = generate_auth_token()
    url = f'http://127.0.0.1:{APP_PORT}{handler}'

    if set_token:
        cookies[acm.AUTH_COOKIE_NAME] = auth_token

    return requests.request(method, url, cookies=cookies, headers=headers, allow_redirects=False, data=data)


class TestIndexPage:
    def test_no_auth(self):
        res = make_app_request('/', set_token=False)

        assert res.status_code == 200
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert len(res.headers['content-security-policy']) > 0
        assert res.headers['x-frame-options'] == 'deny'

        assert '<!-- Page: Auth form -->' in res.text

    def test_main(self):
        res = make_app_request('/')

        assert res.status_code == 200
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert len(res.headers['content-security-policy']) > 0
        assert res.headers['x-frame-options'] == 'deny'

        assert '<!-- Page: User panel -->' in res.text


class TestLoginPage:
    def test_main(self):
        res = make_app_request('/login', method='POST', cookies={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, data={
            'login': 'test',
            'password': 'test',
            'return-path': 'http://foo',
            acm.CSRF_FIELD_NAME: common.get_csrf_token(),
        }, set_token=False)

        assert res.status_code == 200
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert '<!-- Page: TOTP form -->' in res.text

    def test_no_csrf_cookie(self):
        res = make_app_request('/login', method='POST', data={
            'login': 'test',
            'password': 'test',
            'return-path': 'http://foo',
            acm.CSRF_FIELD_NAME: common.get_csrf_token(),
        }, set_token=False)

        assert res.status_code == 403
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert 'No CSRF token' in res.text

    def test_no_csrf_field(self):
        res = make_app_request('/login', method='POST', cookies={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, data={
            'login': 'test',
            'password': 'test',
            'return-path': 'http://foo',
        }, set_token=False)

        assert res.status_code == 403
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert 'No CSRF token' in res.text

    def test_no_login(self):
        res = make_app_request('/login', method='POST', cookies={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, data={
            'password': 'test',
            'return-path': 'http://foo',
            acm.CSRF_FIELD_NAME: common.get_csrf_token(),
        }, set_token=False)

        assert res.status_code == 400
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert 'No auth info' in res.text

    def test_no_password(self):
        res = make_app_request('/login', method='POST', cookies={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, data={
            'login': 'test',
            'return-path': 'http://foo',
            acm.CSRF_FIELD_NAME: common.get_csrf_token(),
        }, set_token=False)

        assert res.status_code == 400
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert 'No auth info' in res.text

    def test_wrong_login(self):
        res = make_app_request('/login', method='POST', cookies={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, data={
            'login': 'invalid-login',
            'password': 'test',
            'return-path': 'http://foo',
            acm.CSRF_FIELD_NAME: common.get_csrf_token(),
        }, set_token=False)

        assert res.status_code == 403
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert 'User is not found' in res.text

    def test_wrong_method(self):
        res = make_app_request('/login', method='GET')

        assert res.status_code == 405
        assert res.headers['content-type'] == 'text/html; charset=utf-8'

        assert '<title>405 Method Not Allowed</title>' in res.text


class TestOtpPage:
    def test_auth_process(self):
        auth_id = self._log_in()

        res = make_app_request('/submit-totp', method='POST', cookies={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, data={
            'login': 'test',
            'password': self._get_otp(),
            'auth_id': auth_id,
            'return-path': 'http://foo',
            acm.CSRF_FIELD_NAME: common.get_csrf_token(),
        }, set_token=False)

        assert res.status_code == 302
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert res.headers['location'] == 'http://foo'
        assert 'Redirecting...' in res.text

        message = url_parse.unquote(res.headers['x-login-message'])
        assert 'New login success' in message
        assert 'IP:' in message
        assert 'Browser:' in message

    def test_no_login(self):
        auth_id = self._log_in()

        res = make_app_request('/submit-totp', method='POST', cookies={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, data={
            'password': self._get_otp(),
            'auth_id': auth_id,
            'return-path': 'http://foo',
            acm.CSRF_FIELD_NAME: common.get_csrf_token(),
        }, set_token=False)

        assert res.status_code == 400
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert 'No auth info' in res.text

    def test_no_auth_id(self):
        self._log_in()

        res = make_app_request('/submit-totp', method='POST', cookies={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, data={
            'login': 'test',
            'password': self._get_otp(),
            'return-path': 'http://foo',
            acm.CSRF_FIELD_NAME: common.get_csrf_token(),
        }, set_token=False)

        assert res.status_code == 400
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert 'No auth info' in res.text

    def test_wrong_auth_id(self):
        self._log_in()

        res = make_app_request('/submit-totp', method='POST', cookies={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, data={
            'login': 'test',
            'password': self._get_otp(),
            'auth_id': 'wrong-auth-id',
            'return-path': 'http://foo',
            acm.CSRF_FIELD_NAME: common.get_csrf_token(),
        }, set_token=False)

        assert res.status_code == 400
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert 'No auth info' in res.text

    def test_no_password(self):
        auth_id = self._log_in()

        res = make_app_request('/submit-totp', method='POST', cookies={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, data={
            'login': 'test',
            'auth_id': auth_id,
            'return-path': 'http://foo',
            acm.CSRF_FIELD_NAME: common.get_csrf_token(),
        }, set_token=False)

        assert res.status_code == 400
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert 'No auth info' in res.text

    def test_wrong_login(self):
        auth_id = self._log_in()

        res = make_app_request('/submit-totp', method='POST', cookies={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, data={
            'login': 'invalid-login',
            'password': self._get_otp(),
            'auth_id': auth_id,
            'return-path': 'http://foo',
            acm.CSRF_FIELD_NAME: common.get_csrf_token(),
        }, set_token=False)

        assert res.status_code == 403
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert 'User is not found' in res.text

    def test_wrong_password(self):
        auth_id = self._log_in()

        res = make_app_request('/submit-totp', method='POST', cookies={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, data={
            'login': 'test',
            'password': '123456',
            'auth_id': auth_id,
            'return-path': 'http://foo',
            acm.CSRF_FIELD_NAME: common.get_csrf_token(),
        }, set_token=False)

        assert res.status_code == 403
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert 'Wrong OTP' in res.text

    def test_no_csrf_cookie(self):
        auth_id = self._log_in()

        res = make_app_request('/submit-totp', method='POST', data={
            'login': 'test',
            'password': self._get_otp(),
            'auth_id': auth_id,
            'return-path': 'http://foo',
            acm.CSRF_FIELD_NAME: common.get_csrf_token(),
        }, set_token=False)

        assert res.status_code == 403
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert 'No CSRF token' in res.text

    def test_no_csrf_field(self):
        auth_id = self._log_in()

        res = make_app_request('/submit-totp', method='POST', cookies={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, data={
            'login': 'test',
            'password': self._get_otp(),
            'auth_id': auth_id,
            'return-path': 'http://foo',
        }, set_token=False)

        assert res.status_code == 403
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert 'No CSRF token' in res.text

    def test_wrong_method(self):
        res = make_app_request('/submit-totp', method='GET')

        assert res.status_code == 405
        assert res.headers['content-type'] == 'text/html; charset=utf-8'

        assert '<title>405 Method Not Allowed</title>' in res.text

    def _log_in(self, login='test'):
        res = make_app_request('/login', method='POST', cookies={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, data={
            'login': login,
            'password': 'test',
            'return-path': 'http://foo',
            acm.CSRF_FIELD_NAME: common.get_csrf_token(),
        }, set_token=False)

        assert res.status_code == 200

        auth_id = res.headers.get('x-auth-id')
        assert auth_id is not None

        return auth_id

    def _get_otp(self, login='test'):
        return pyotp.TOTP(AUTH_INFO_DATA[login]['totp_secret']).now()


class TestLogout:
    def test_main(self):
        res = make_app_request('/logout', method='POST', cookies={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, data={
            'login': 'test',
            'password': 'test',
            'return-path': 'http://foo',
            acm.CSRF_FIELD_NAME: common.get_csrf_token(),
        })

        assert res.status_code == 302
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert res.headers['location'] == 'http://foo'
        assert f'{acm.AUTH_COOKIE_NAME}=;' in res.headers['set-cookie']
        assert 'Redirecting...' in res.text


class TestGetPublicKey:
    def test_main(self):
        res = make_app_request('/get-public-key', set_token=False)

        assert res.status_code == 200
        assert res.headers['content-type'] == 'text/plain; charset=utf-8'

        assert '-----BEGIN PUBLIC KEY-----' in res.text
        assert '-----END PUBLIC KEY-----' in res.text

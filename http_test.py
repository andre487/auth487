import os
import requests
from cli_tasks import common
from lib.auth487 import common as acm

APP_PORT = int(os.getenv('APP_PORT', 8080))


def make_app_request(handler, method='GET', data=None, headers=None, cookies=None, set_token=True):
    if cookies is None:
        cookies = {}

    auth_token = common.get_auth_token()
    url = f'http://127.0.0.1:{APP_PORT}{handler}'

    if set_token:
        cookies[acm.AUTH_COOKIE_NAME] = auth_token

    return requests.request(method, url, cookies=cookies, headers=headers, allow_redirects=False, data=data)


class TestIndexPage:
    def test_no_auth(self):
        res = make_app_request('/', set_token=False)

        assert res.status_code == 200
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert res.headers['content-security-policy'] == (
            "default-src 'none'; "
            "style-src 'self'; "
            "script-src 'self'; "
            "img-src 'self';"
        )
        assert res.headers['x-frame-options'] == 'deny'

        assert '<!-- Page: Auth form -->' in res.text

    def test_main(self):
        res = make_app_request('/')

        assert res.status_code == 200
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert res.headers['content-security-policy'] == (
            "default-src 'none'; "
            "style-src 'self'; "
            "script-src 'self'; "
            "img-src 'self';"
        )
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
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, set_token=False)

        assert res.status_code == 302
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert res.headers['location'] == 'http://foo'
        assert 'Redirecting...' in res.text

    def test_no_csrf_cookie(self):
        res = make_app_request('/login', method='POST', data={
            'login': 'test',
            'password': 'test',
            'return-path': 'http://foo',
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
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
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
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
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
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
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, set_token=False)

        assert res.status_code == 403
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert 'Wrong login or password' in res.text

    def test_wrong_password(self):
        res = make_app_request('/login', method='POST', cookies={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, data={
            'login': 'test',
            'password': 'invalid-password',
            'return-path': 'http://foo',
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, set_token=False)

        assert res.status_code == 403
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert 'Wrong login or password' in res.text

    def test_wrong_method(self):
        res = make_app_request('/login', method='GET')

        assert res.status_code == 405
        assert res.headers['content-type'] == 'text/html; charset=utf-8'

        assert '<title>405 Method Not Allowed</title>' in res.text


class TestLogout:
    def test_main(self):
        res = make_app_request('/logout', method='POST', cookies={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, data={
            'login': 'test',
            'password': 'test',
            'return-path': 'http://foo',
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        })

        assert res.status_code == 302
        assert res.headers['content-type'] == 'text/html; charset=utf-8'
        assert res.headers['location'] == 'http://foo'
        assert f'{acm.AUTH_COOKIE_NAME}=;' in res.headers['set-cookie']
        assert 'Redirecting...' in res.text


class TestGetAuthInfo:
    def test_no_auth(self):
        res = make_app_request('/get-auth-info', set_token=False)

        assert res.status_code == 302
        assert 'Redirecting...' in res.text

    def test_main(self):
        res = make_app_request('/get-auth-info')

        assert res.status_code == 200
        assert res.headers['content-type'] == 'application/json; charset=utf-8'

        ans = res.json()
        assert ans.get('login') == 'test-user'


class TestGetPublicKey:
    def test_main(self):
        res = make_app_request('/get-public-key', set_token=False)

        assert res.status_code == 200
        assert res.headers['content-type'] == 'text/plain; charset=utf-8'

        assert '-----BEGIN RSA PUBLIC KEY-----' in res.text
        assert '-----END RSA PUBLIC KEY-----' in res.text


class TestGetToken:
    def test_no_auth(self):
        res = make_app_request('/get-token', method='POST', cookies={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, data={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, set_token=False)

        assert res.status_code == 302
        assert 'Redirecting...' in res.text

    def test_main(self):
        res = make_app_request('/get-token', method='POST', cookies={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        }, data={
            acm.CSRF_COOKIE_NAME: common.get_csrf_token(),
        })

        assert res.status_code == 200
        assert res.headers['content-type'] == 'text/html; charset=utf-8'

        assert res.headers['content-security-policy'] == (
            "default-src 'none'; "
            "style-src 'self'; "
            "script-src 'self'; "
            "img-src 'self';"
        )
        assert res.headers['x-frame-options'] == 'deny'

        assert '<!-- Page: Show token -->' in res.text

    def test_wrong_method(self):
        res = make_app_request('/get-token', method='GET')

        assert res.status_code == 405
        assert res.headers['content-type'] == 'text/html; charset=utf-8'

        assert '<title>405 Method Not Allowed</title>' in res.text

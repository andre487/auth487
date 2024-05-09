import os
from datetime import UTC, datetime, timedelta
from urllib import request

from authlib.jose import jwt
from authlib.jose.errors import BadSignatureError, DecodeError

AUTH_DOMAIN = os.environ.get('AUTH_DOMAIN', 'http://127.0.0.1:5487')
AUTH_DEV_MODE = os.getenv('AUTH_DEV_MODE') == '1'

AUTH_COOKIE_NAME = '__Secure-Auth-Token'
CSRF_COOKIE_NAME = '__Host-Csrf-Token'
CSRF_FIELD_NAME = 'csrf_token'
if AUTH_DEV_MODE:
    AUTH_COOKIE_NAME = 'Dev-Auth-Token'
    CSRF_COOKIE_NAME = 'Dev-Csrf-Token'

PUBLIC_KEY_FILE = os.environ.get('AUTH_PUBLIC_KEY_FILE')
PUBLIC_KEY_CACHE_TIME = 15

_public_key_cache = None
_public_key_time = 0


def get_public_key():
    if public_key := _get_public_key_from_fs():
        return public_key
    return _download_public_key()


def _get_public_key_from_fs():
    if not PUBLIC_KEY_FILE:
        return None

    with open(PUBLIC_KEY_FILE) as fp:
        return fp.read()


def _download_public_key():
    global _public_key_cache, _public_key_time

    now = datetime.now(tz=UTC).timestamp()
    if now - _public_key_time <= PUBLIC_KEY_CACHE_TIME:
        return _public_key_cache

    _public_key_cache = request.urlopen(AUTH_DOMAIN + '/get-public-key').read()
    _public_key_time = now

    return _public_key_cache


def extract_auth_info(auth_token):
    try:
        claims = jwt.decode(auth_token, get_public_key())
    except (BadSignatureError, DecodeError, ValueError):
        return None

    return dict(claims)


def has_credentials(get_auth_token):
    return bool(get_auth_token())


def is_authenticated(get_auth_token):
    auth_token = get_auth_token()
    if not auth_token:
        return False

    auth_info = extract_auth_info(auth_token)
    return bool(auth_info)


def get_auth_info_from_token(get_auth_token):
    auth_token = get_auth_token()
    if not auth_token:
        return None

    return extract_auth_info(auth_token)


def create_auth_token(login, auth_data, private_key):
    now = datetime.now(tz=UTC)
    now_ts = int(now.timestamp())

    exp_days = auth_data.get('expiration_days', 1)
    exp_ts = int((now + timedelta(days=exp_days)).timestamp())

    header = {'alg': 'ES512'}
    payload = {
        'iat': now_ts,
        'nbf': now_ts,
        'exp': exp_ts,
        'name': login,
        'access': auth_data['access'],
    }

    return jwt.encode(header, payload, private_key).decode('utf8')


def _raise_not_implemented():
    raise NotImplementedError('Use framework specific modules')


check_csrf_token = \
    set_csrf_token = \
    get_csrf_token = \
    check_brute_force = \
    protected_from_brute_force = _raise_not_implemented

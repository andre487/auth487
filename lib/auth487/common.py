import os
from datetime import datetime
from urllib import request

from authlib.jose import jwt
from authlib.jose.errors import BadSignatureError, DecodeError

AUTH_COOKIE_NAME = 'AUTH_TOKEN'
CSRF_COOKIE_NAME = 'CSRF_TOKEN'

AUTH_DOMAIN = os.environ.get('AUTH_DOMAIN', 'http://localhost:5487')

PRIVATE_KEY_FILE = os.environ.get('AUTH_PRIVATE_KEY_FILE')
PUBLIC_KEY_FILE = os.environ.get('AUTH_PUBLIC_KEY_FILE')

PRIVATE_KEY = None
if PRIVATE_KEY_FILE:
    with open(PRIVATE_KEY_FILE) as fp:
        PRIVATE_KEY = fp.read()

PUBLIC_KEY = None
if PUBLIC_KEY_FILE:
    with open(PUBLIC_KEY_FILE) as fp:
        PUBLIC_KEY = fp.read()

PUBLIC_KEY_CACHE_TIME = 300

_public_key_cache = None
_public_key_time = 0


def get_public_key():
    if PUBLIC_KEY is not None:
        return PUBLIC_KEY

    return download_public_key()


def download_public_key():
    global _public_key_cache, _public_key_time

    now = datetime.utcnow().timestamp()
    if now - _public_key_time <= PUBLIC_KEY_CACHE_TIME:
        return _public_key_cache

    _public_key_cache = request.urlopen(AUTH_DOMAIN + '/get-public-key').read()
    _public_key_time = now

    return _public_key_cache


def extract_auth_info(auth_token):
    try:
        claims = jwt.decode(auth_token, get_public_key())
    except (BadSignatureError, DecodeError):
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


def _raise_not_implemented():
    raise NotImplementedError('Use framework specific modules')


check_csrf_token = \
    set_csrf_token = \
    get_csrf_token = \
    check_brute_force = \
    protected_from_brute_force = \
    get_auth_token = _raise_not_implemented


def create_auth_token(login, auth_data, private_key):
    header = {'alg': 'RS256'}
    payload = {
        'login': login,
        'access': auth_data['access'],
    }
    return jwt.encode(header, payload, private_key)

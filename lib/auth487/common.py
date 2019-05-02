import os

from authlib.jose import jwt
from authlib.jose.errors import BadSignatureError

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


def extract_auth_info(auth_token):
    try:
        claims = jwt.decode(auth_token, PUBLIC_KEY)
    except BadSignatureError:
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

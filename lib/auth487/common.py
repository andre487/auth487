import enum
import os
import pytz
import typing
from datetime import datetime, timedelta
from urllib import request

from authlib.jose import jwt
from authlib.jose.errors import BadSignatureError, DecodeError

AUTH_BASE_URL = os.getenv('AUTH_BASE_URL', 'http://127.0.0.1:5487')
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


def is_authenticated(get_auth_token):
    auth_data = check_auth_info_from_token(get_auth_token)
    return auth_data.decline_reason == AuthTokenDeclineReason.NONE


class AuthTokenDeclineReason(enum.Enum):
    NONE = enum.auto()
    NO_TOKEN = enum.auto()
    NO_ACCESS = enum.auto()
    INVALID_TOKEN = enum.auto()
    IAT_INVALID = enum.auto()
    NBF_INVALID = enum.auto()
    EXP_INVALID = enum.auto()


class AuthInfoData(typing.NamedTuple):
    token: str | None = None
    auth_info: dict | None = None
    decline_reason: AuthTokenDeclineReason = AuthTokenDeclineReason.NONE


def check_auth_info_from_token(get_auth_token, access=()):
    auth_token = get_auth_token()
    if not auth_token:
        return AuthInfoData(decline_reason=AuthTokenDeclineReason.NO_TOKEN)

    auth_info = _extract_auth_info(auth_token)
    if not auth_info:
        return AuthInfoData(decline_reason=AuthTokenDeclineReason.INVALID_TOKEN)

    now = datetime.now(tz=pytz.utc).timestamp()
    if not (issued_at := auth_info.get('iat')) or issued_at > now:
        return AuthInfoData(decline_reason=AuthTokenDeclineReason.IAT_INVALID)

    if not (not_before := auth_info.get('nbf')) or not_before > now:
        return AuthInfoData(decline_reason=AuthTokenDeclineReason.NBF_INVALID)

    if not (expires := auth_info.get('exp')) or expires < now:
        return AuthInfoData(decline_reason=AuthTokenDeclineReason.EXP_INVALID)

    from .data_handler import has_access_to

    for rule in access:
        if not has_access_to(auth_info, rule):
            return AuthInfoData(decline_reason=AuthTokenDeclineReason.NO_ACCESS)

    return AuthInfoData(
        token=auth_token,
        auth_info=auth_info,
    )


def create_auth_token(login, auth_data, private_key):
    if not private_key:
        raise Exception('No private key')

    now = datetime.now(tz=pytz.utc)
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


def _get_public_key_from_fs():
    if not PUBLIC_KEY_FILE:
        return None

    with open(PUBLIC_KEY_FILE) as fp:
        return fp.read()


def _download_public_key():
    global _public_key_cache, _public_key_time

    now = datetime.now(tz=pytz.utc).timestamp()
    if now - _public_key_time <= PUBLIC_KEY_CACHE_TIME:
        return _public_key_cache

    with request.urlopen(AUTH_BASE_URL + '/get-public-key') as resp:
        _public_key_cache = resp.read()
    _public_key_time = now

    return _public_key_cache


def _extract_auth_info(auth_token) -> dict[str, typing.Any] | None:
    try:
        claims = jwt.decode(auth_token, get_public_key())
    except (BadSignatureError, DecodeError, ValueError):
        return None

    return dict(claims)


def _raise_not_implemented():
    raise NotImplementedError('Use framework specific modules')


check_csrf_token = \
    set_csrf_token = \
    get_csrf_token = \
    check_brute_force = \
    protected_from_brute_force = _raise_not_implemented

import logging
import os
import secrets
import ssl
import pyotp
import pymongo
from .common import AUTH_DEV_MODE


def get_env_param(name, def_val=None, try_file=False):
    val = os.getenv(name, def_val)

    if try_file and val and os.path.isfile(val):
        with open(val) as fp:
            return fp.read().strip()

    return val


CONNECT_TIMEOUT = 500
AUTH_MISTAKES_TO_BAN = int(get_env_param('AUTH_MISTAKES_TO_BAN', '10'))
AUTH_BAN_TIME = int(get_env_param('AUTH_BAN_TIME', '60'))

MONGO_HOST = get_env_param('MONGO_HOST', 'localhost', try_file=True)
MONGO_PORT = int(get_env_param('MONGO_PORT', '27017', try_file=True))

MONGO_REPLICA_SET = get_env_param('MONGO_REPLICA_SET', try_file=True)
MONGO_SSL_CERT = get_env_param('MONGO_SSL_CERT', try_file=True)

MONGO_USER = get_env_param('MONGO_USER', try_file=True)
MONGO_PASSWORD = get_env_param('MONGO_PASSWORD', try_file=True)
MONGO_AUTH_SOURCE = get_env_param('MONGO_AUTH_SOURCE', try_file=True)

MONGO_DB_NAME = get_env_param('MONGO_DB_NAME', 'auth487')

_mongo_client = None


def is_remote_addr_clean(remote_addr):
    if not pymongo:
        logging.warning('No MongoDB so remotes are always clean')
        return True

    collection = _get_remote_addr_collection()

    addr_data = collection.find_one({'remote_addr': remote_addr})
    if addr_data is None:
        return True

    if addr_data['mistakes'] >= AUTH_MISTAKES_TO_BAN:
        return False

    return True


def mark_auth_mistake(remote_addr):
    if not pymongo:
        logging.warning("No MongoDB so can't mark auth mistake")
        return

    collection = _get_remote_addr_collection()
    result = collection.update({'remote_addr': remote_addr}, {'$inc': {'mistakes': 1}})

    if not result['updatedExisting']:
        collection.insert({'remote_addr': remote_addr, 'mistakes': 1})


def has_access_to(auth_info, service):
    return bool(auth_info.get('access', {}).get(service))


def get_banned_addresses(auth_info):
    if not has_access_to(auth_info, 'banned_ips'):
        return []

    if not pymongo:
        logging.warning('No MongoDB so banned addresses list is always empty')
        return []

    collection = _get_remote_addr_collection()

    return [doc['remote_addr'] for doc in collection.find({})]


def create_second_factor_record(login, auth_data, password_hash):
    auth_id = secrets.token_hex(32)
    _get_second_factor_collection().insert({
        'login': login,
        'auth_id': auth_id,
        'password_hash': password_hash,
    })

    if AUTH_DEV_MODE:
        totp = pyotp.TOTP(auth_data['totp_secret'])
        logging.info('!!! TOTP: %s', totp.now())

    return auth_id


def get_second_factor_record(login, auth_id):
    return _get_second_factor_collection().find_one({
        'login': login,
        'auth_id': auth_id,
    })


def remove_second_factor_record(login, auth_id):
    return _get_second_factor_collection().remove({
        'login': login,
        'auth_id': auth_id,
    })


def _get_mongo_client():
    global _mongo_client
    if _mongo_client:
        return _mongo_client

    logging.info('Connecting to MongoDB: %s:%s', MONGO_HOST, MONGO_PORT)

    mongo_options = dict(
        connectTimeoutMS=CONNECT_TIMEOUT,
        authSource=MONGO_DB_NAME,
    )

    if MONGO_REPLICA_SET:
        mongo_options['replicaSet'] = MONGO_REPLICA_SET

    _mongo_client = pymongo.MongoClient(
        MONGO_HOST, MONGO_PORT,
        connect=True,
        username=MONGO_USER,
        password=MONGO_PASSWORD,
        tlsCAFile=MONGO_SSL_CERT,
        ssl_cert_reqs=ssl.CERT_REQUIRED if MONGO_SSL_CERT else ssl.CERT_NONE,
        **mongo_options
    )

    return _mongo_client


def _get_second_factor_collection():
    client = _get_mongo_client()
    collection = client[MONGO_DB_NAME]['second_factor']

    collection.create_index([
        ('auth_id', pymongo.ASCENDING),
    ], background=True, unique=True, expireAfterSeconds=300)

    return collection


def _get_remote_addr_collection():
    client = _get_mongo_client()
    collection = client[MONGO_DB_NAME]['remote_addresses']

    collection.create_index(
        [('remote_addr', pymongo.ASCENDING)],
        background=True, unique=True,
        expireAfterSeconds=AUTH_BAN_TIME,
    )

    return collection

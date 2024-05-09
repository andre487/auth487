import logging
import os
import secrets
import typing as tp

import pymongo
import pyotp

from .common import AUTH_DEV_MODE

CONNECT_TIMEOUT = 500
AUTH_MISTAKES_TO_BAN = int(os.getenv('AUTH_MISTAKES_TO_BAN', '10'))
AUTH_BAN_TIME = int(os.getenv('AUTH_BAN_TIME', '60'))

_mongo_client = None
_prev_credentials = None


def is_remote_addr_clean(remote_addr):
    collection = _get_remote_addr_collection()

    addr_data = collection.find_one({'remote_addr': remote_addr})
    if addr_data is None:
        return True

    if addr_data['mistakes'] >= AUTH_MISTAKES_TO_BAN:
        return False

    return True


def mark_auth_mistake(remote_addr):
    _get_remote_addr_collection().update_one({'remote_addr': remote_addr}, {'$inc': {'mistakes': 1}}, upsert=True)


def has_access_to(auth_info, service):
    return bool(auth_info.get('access', {}).get(service))


def get_banned_addresses(auth_info):
    if not has_access_to(auth_info, 'banned_ips'):
        return []

    collection = _get_remote_addr_collection()

    return [doc['remote_addr'] for doc in collection.find({})]


def create_second_factor_record(login, auth_data, password_hash):
    auth_id = secrets.token_hex(32)
    _get_second_factor_collection().insert_one({
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
    return _get_second_factor_collection().delete_many({
        'login': login,
        'auth_id': auth_id,
    })


class MongoCredentials(tp.NamedTuple):
    mongo_host: str
    mongo_port: int
    mongo_replica_set: str | None
    mongo_ssl_cert: str | None
    mongo_user: str | None
    mongo_password: str | None
    mongo_auth_source: str | None
    mongo_db_name: str | None
    changed: bool | None = None


def _get_mongo_db_name() -> str:
    return _get_env_param('MONGO_DB_NAME', 'auth487')


def _get_mongo_credentials() -> MongoCredentials:
    global _prev_credentials

    mongo_host = _get_env_param('MONGO_HOST', 'localhost')
    mongo_port = int(_get_env_param('MONGO_PORT', '27017'))

    mongo_replica_set = _get_env_param('MONGO_REPLICA_SET')
    mongo_ssl_cert = _get_env_param('MONGO_SSL_CERT')

    mongo_user = _get_env_param('MONGO_USER')
    mongo_password = _get_env_param('MONGO_PASSWORD')
    mongo_auth_source = _get_env_param('MONGO_AUTH_SOURCE')

    mongo_db_name = _get_mongo_db_name()

    credentials = MongoCredentials(
        mongo_host,
        mongo_port,
        mongo_replica_set,
        mongo_ssl_cert,
        mongo_user,
        mongo_password,
        mongo_auth_source,
        mongo_db_name,
    )

    changed = credentials != _prev_credentials
    _prev_credentials = credentials

    credentials = list(credentials)
    credentials[-1] = changed

    return MongoCredentials(*credentials)


def _get_env_param(name, def_val=None):
    val = os.getenv(name, def_val)

    if val and os.path.isfile(val):
        with open(val) as fp:
            return fp.read().strip()

    return val


def _get_mongo_client():
    global _mongo_client

    (
        mongo_host,
        mongo_port,
        mongo_replica_set,
        mongo_ssl_cert,
        mongo_user,
        mongo_password,
        mongo_auth_source,
        mongo_db_name,
        mongo_changed,
    ) = _get_mongo_credentials()

    if _mongo_client and not mongo_changed:
        return _mongo_client

    if _mongo_client and mongo_changed:
        logging.info('Mongo credentials changed, reconnect')
        _mongo_client.close()

    logging.info('Connecting to MongoDB: %s:%s', mongo_host, mongo_port)

    mongo_options = dict(
        connectTimeoutMS=CONNECT_TIMEOUT,
        authSource=mongo_db_name,
    )

    if mongo_replica_set:
        mongo_options['replicaSet'] = mongo_replica_set

    _mongo_client = pymongo.MongoClient(
        mongo_host, mongo_port,
        connect=True,
        username=mongo_user,
        password=mongo_password,
        tlsCAFile=mongo_ssl_cert,
        **mongo_options
    )

    return _mongo_client


def _get_second_factor_collection():
    client = _get_mongo_client()
    mongo_db_name = _get_mongo_db_name()
    collection = client[mongo_db_name]['second_factor']

    collection.create_index([
        ('auth_id', pymongo.ASCENDING),
    ], background=True, unique=True, expireAfterSeconds=300)

    return collection


def _get_remote_addr_collection():
    client = _get_mongo_client()
    mongo_db_name = _get_mongo_db_name()
    collection = client[mongo_db_name]['remote_addresses']

    collection.create_index(
        [('remote_addr', pymongo.ASCENDING)],
        background=True, unique=True,
        expireAfterSeconds=AUTH_BAN_TIME,
    )

    return collection

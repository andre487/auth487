import logging
import os

try:
    import pymongo
except ImportError as e:
    logging.debug("PyMongo is not presented so don't use data handling")
    pymongo = None

CONNECT_TIMEOUT = 2000
AUTH_MISTAKES_TO_BAN = int(os.environ.get('AUTH_MISTAKES_TO_BAN', 5))
AUTH_BAN_TIME = int(os.environ.get('AUTH_BAN_TIME', 86400))

MONGO_HOST = os.environ.get('MONGO_HOST', 'localhost')
MONGO_PORT = int(os.environ.get('MONGO_PORT', 27017))
MONGO_LOGIN = os.environ.get('MONGO_LOGIN')
MONGO_PASSWORD = os.environ.get('MONGO_PASSWORD')
MONGO_DB_NAME = os.environ.get('AUTH_MONGO_DB_NAME', 'auth487')

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


def get_banned_addresses():
    if not pymongo:
        logging.warning('No MongoDB so banned addresses list is always empty')
        return True

    collection = _get_remote_addr_collection()

    return [doc['remote_addr'] for doc in collection.find({})]


def _get_mongo_client():
    global _mongo_client
    if _mongo_client:
        return _mongo_client

    logging.info('Connecting to MongoDB: %s:%s', MONGO_HOST, MONGO_PORT)

    _mongo_client = pymongo.MongoClient(
        MONGO_HOST, MONGO_PORT,
        connect=True,
        connectTimeoutMS=CONNECT_TIMEOUT,
        username=MONGO_LOGIN,
        password=MONGO_PASSWORD,
    )

    return _mongo_client


def _get_remote_addr_collection():
    client = _get_mongo_client()
    collection = client[MONGO_DB_NAME]['remote_addresses']

    collection.create_index(
        [('remote_addr', pymongo.ASCENDING)],
        background=True, unique=True,
        expireAfterSeconds=AUTH_BAN_TIME,
    )

    return collection

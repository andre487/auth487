import argparse
import json
import logging
import os

import pymongo

MONGO_HOST = os.environ.get('MONGO_HOST', 'localhost')
MONGO_PORT = int(os.environ.get('MONGO_PORT', 27017))
MONGO_LOGIN = os.environ.get('MONGO_LOGIN')
MONGO_PASSWORD = os.environ.get('MONGO_PASSWORD')
MONGO_DB_NAME = os.environ.get('MONGO_DB_NAME', 'auth487_docker_test')

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s\t%(name)s\t%(message)s')


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('action', choices=('setup', 'tear-down'))
    arg_parser.add_argument('--force', action='store_true')

    args = arg_parser.parse_args()

    if args.action == 'setup':
        setup(args.force)
    elif args.action == 'tear-down':
        tear_down()


def setup(force):
    if force:
        tear_down()

    logging.info('Setting up DB %s', MONGO_DB_NAME)

    fixture_file = os.path.join(os.path.dirname(__file__), 'fixture.json')
    with open(fixture_file) as fd:
        fixture_data = json.load(fd)

    db = get_mongo_db()

    for collection_name, data in fixture_data.items():
        collection = db[collection_name]
        if collection.estimated_document_count():
            continue

        logging.info('Setting up collection %s', collection_name)
        collection.insert_many(data)


def tear_down():
    logging.info('Tearing down DB %s', MONGO_DB_NAME)

    client = get_mongo_client()
    client.drop_database(MONGO_DB_NAME)


def get_mongo_db():
    mongo_client = get_mongo_client()
    return mongo_client[MONGO_DB_NAME]


def get_mongo_client():
    return pymongo.MongoClient(
        MONGO_HOST, MONGO_PORT,
        connect=True,
        username=MONGO_LOGIN,
        password=MONGO_PASSWORD,
    )


if __name__ == '__main__':
    main()

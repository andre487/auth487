#!/usr/bin/env python3
import base64
import json
import logging
import os
import subprocess as sp
import time
import typing as tp
import urllib.request

import click

LOCKBOX_SECRET_URL = 'https://payload.lockbox.api.cloud.yandex.net/lockbox/v1/secrets'

op_secrets_dir = click.option('--secrets-dir', '-d', default='/tmp/secrets')
op_meta_service = click.option('--meta-service', '-m', default='169.254.169.254')
op_dev_run = click.option('--dev-run', is_flag=True)

SECRETS = {
    'auth_info': 'e6q6vfo2vo565h0cb0nq',
    'gmail_sender': 'e6qar6a7mkjfu29vpv7b',
}

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s\t%(name)s\t%(message)s')
logger = logging.getLogger('yc_secret_fetcher')


@click.group()
def main() -> None:
    pass


@main.command()
@op_secrets_dir
@op_meta_service
@op_dev_run
@click.argument('free_args', nargs=-1, type=click.UNPROCESSED)
def once(secrets_dir: str, meta_service: str, dev_run: bool, **_kwargs: tp.Any) -> None:
    get_secrets(secrets_dir, meta_service, dev_run)


@main.command()
@op_secrets_dir
@op_meta_service
@click.option('--sync-interval', '-s', default=90.0)
@op_dev_run
@click.argument('free_args', nargs=-1, type=click.UNPROCESSED)
def loop(secrets_dir: str, meta_service: str, sync_interval: float, dev_run: bool, **_kwargs: tp.Any) -> None:
    while True:
        logger.info('Waiting %f seconds...', sync_interval)
        time.sleep(sync_interval)
        get_secrets(secrets_dir, meta_service, dev_run)


def get_secrets(secrets_dir: str, meta_service: str, dev_run: bool) -> None:
    logger.info('Getting secrets')

    os.makedirs(secrets_dir, exist_ok=True)
    os.chmod(secrets_dir, 0o700)

    iam_token = get_iam_token(meta_service, dev_run)
    for sec_name, sec_id in SECRETS.items():
        logger.info('Get %s, id=%s', sec_name, sec_id)
        data = request_lockbox(iam_token, sec_id)

        sec_dir = os.path.join(secrets_dir, sec_name)
        os.makedirs(sec_dir, exist_ok=True)
        os.chmod(sec_dir, 0o700)

        for sec_item, sec_val in data.items():
            sec_file = os.path.join(sec_dir, sec_item)

            ex_val = ...
            ex_file = False
            if os.path.exists(sec_file):
                ex_file = True
                with open(sec_file, 'rb') as fp:
                    ex_val = fp.read()

            if sec_val == ex_val:
                logger.info('Secret %s:%s already exists and not changed', sec_name, sec_item)
            else:
                if ex_file:
                    logger.info('Secret %s:%s changed, rewriting', sec_name, sec_item)
                else:
                    logger.info('Secret %s:%s does not exist, creating', sec_name, sec_item)
                with open(sec_file, 'wb') as fp:
                    fp.write(sec_val)
                os.chmod(sec_file, 0o600)


def get_iam_token(meta_service: str, dev_run: bool):
    if dev_run:
        if val := os.getenv('IAM_TOKEN'):
            return val
        return sp.check_output(['yc', 'iam', 'create-token'], encoding='utf8').strip()

    url = f'http://{meta_service}/computeMetadata/v1/instance/service-accounts/default/token'
    req = urllib.request.Request(
        method='GET',
        url=url,
        headers={'Metadata-Flavor': 'Google'},
    )
    with urllib.request.urlopen(req) as resp:
        resp_data = json.loads(resp.read())

    token = resp_data.get('access_token')
    if not token:
        raise RuntimeError(f'There is no access token in result: {resp_data}')

    return token


def request_lockbox(iam_token: str, sec_id: str) -> dict[str, bytes]:
    url = f'{LOCKBOX_SECRET_URL}/{sec_id}/payload'

    req = urllib.request.Request(
        method='GET',
        url=url,
        headers={'Authorization': f'Bearer {iam_token}'},
    )

    try:
        with urllib.request.urlopen(req) as resp:
            resp_data = json.loads(resp.read())
    except urllib.request.HTTPError as e:
        logging.error('Secret %s error: %s', sec_id, e.read().decode('utf8', errors='backslashreplace'))
        raise Exception(f'Secret retrieving error: {e}') from None

    sec_data = {}
    for cur_data in resp_data['entries']:
        name = cur_data['key']
        if val := cur_data.get('textValue'):
            sec_data[name] = val.encode('utf8')
        elif val := cur_data.get('binaryValue'):
            sec_data[name] = base64.b64decode(val)
    return sec_data


if __name__ == '__main__':
    main()

import atexit
import json
import logging
import os
import shutil
import socket
import subprocess
from functools import partial

logging.basicConfig(level=logging.INFO)

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
VENV_DIR = os.path.join(PROJECT_DIR, '.venv')
PYTHON = os.path.join(VENV_DIR, 'bin', 'python')
TEST_DATA_DIR = os.path.join(PROJECT_DIR, 'test_data')
SECRET_DIR = os.path.join(PROJECT_DIR, '.secret')

DOCKER_IMAGE_NAME = 'andre487/auth487:latest'
DOCKER_MONGO_NAME = 'auth487-mongo'
DOCKER_APP_NAME = 'auth487-test'
DEV_DB_NAME = 'auth487'
TEST_DB_NAME = 'auth487_test'

DEFAULT_APP_ENV = {
    'MONGO_DB_NAME': TEST_DB_NAME,
    'FLASK_APP': 'app.py',
    'FLASK_ENV': 'dev',
    'FLASK_DEBUG': '1',
    'AUTH_DOMAIN': 'https://auth.andre.life',
    'AUTH_PRIVATE_KEY_FILE': os.path.join(TEST_DATA_DIR, 'auth_keys', 'auth_key.pem'),
    'AUTH_PUBLIC_KEY_FILE': os.path.join(TEST_DATA_DIR, 'auth_keys', 'auth_key.pub.pem'),
    'AUTH_INFO_FILE': os.path.join(TEST_DATA_DIR, 'test-auth-info.json'),
}


def prepare_virtual_env(c, recreate_venv):
    os.chdir(PROJECT_DIR)

    if os.path.exists(VENV_DIR):
        if recreate_venv:
            shutil.rmtree(VENV_DIR)
        else:
            return

    c.run(f'python3.10 -m venv --copies --upgrade-deps --clear {VENV_DIR}')
    c.run(f'{PYTHON} -m pip install -r {PROJECT_DIR}/requirements.txt')


def start_dev_instance(port, db_name=DEV_DB_NAME, force_db_cleaning=False):
    mongo_port = run_mongo(force_db_cleaning=force_db_cleaning, db_name=db_name)

    env = DEFAULT_APP_ENV.copy()
    env['MONGO_DB_NAME'] = db_name
    env['AUTH_DOMAIN'] = f'http://127.0.0.1:{port}'
    env['AUTH_DEV_MODE'] = '1'
    env.update(os.environ)
    env['MONGO_PORT'] = mongo_port

    return subprocess.Popen(
        (PYTHON, '-m', 'flask', 'run', '-p', str(port)),
        cwd=PROJECT_DIR,
        env=env,
    )


def start_docker_instance(
    port,
    db_name=DEV_DB_NAME,
    force_db_cleaning=False,
    as_daemon=False,
):
    logging.info('Starting Docker app instance')
    run_mongo(force_db_cleaning=force_db_cleaning, db_name=db_name)

    docker = get_docker()
    cont_id, _ = get_container_data(docker, DOCKER_APP_NAME)
    if cont_id:
        subprocess.check_call((docker, 'rm', '-f', cont_id))

    iam_token = subprocess.check_output(('yc', 'iam', 'create-token'), encoding='utf8').strip()

    daemon_arg = []
    if as_daemon:
        daemon_arg = ['-d']

    cont_id = subprocess.check_output((
        docker, 'run', *daemon_arg, '--name', DOCKER_APP_NAME,
        '--link', DOCKER_MONGO_NAME,
        '-p', f'127.0.0.1:{port}:5000',
        '-v', f'{TEST_DATA_DIR}:/opt/test_data',
        '-e', 'AUTH_PRIVATE_KEY_FILE=/opt/test_data/auth_keys/auth_key.pem',
        '-e', 'AUTH_PUBLIC_KEY_FILE=/opt/test_data/auth_keys/auth_key.pub.pem',
        '-e', f'AUTH_DOMAIN=http://127.0.0.1:{port}',
        '-e', 'AUTH_DEV_MODE=1',
        '-e', 'AUTH_INFO_FILE=/opt/test_data/test-auth-info.json',
        '-e', 'FLASK_APP=app.py',
        '-e', 'FLASK_ENV=dev',
        '-e', 'FLASK_DEBUG=1',
        '-e', f'MONGO_HOST={DOCKER_MONGO_NAME}',
        '-e', f'MONGO_DB_NAME={db_name}',
        '-e', 'SECRETS_DIR=/opt/secrets',
        '-e', 'SECRETS_DEV_RUN=1',
        '-e', f'IAM_TOKEN={iam_token}',
        DOCKER_IMAGE_NAME,
    )).strip()

    atexit.register(partial(remove_docker_container, cont_id))
    atexit.register(partial(get_docker_instance_logs, cont_id))


def get_docker_instance_logs(cont_id):
    docker = get_docker()
    subprocess.check_call((docker, 'logs', cont_id))


def remove_docker_container(cont_id):
    logging.info('Removing Docker container %s', cont_id)
    docker = get_docker()
    subprocess.check_call((docker, 'rm', '-f', cont_id))


def run_mongo(force_db_cleaning=False, db_name=DEV_DB_NAME):
    logging.info('Start MongoDB using Docker')

    docker = get_docker()
    cont_id, is_running = get_container_data(docker, DOCKER_MONGO_NAME)
    if not cont_id:
        subprocess.check_output((docker, 'run', '-d', '-P', '--name', DOCKER_MONGO_NAME, 'mongo:4'))
        cont_id, is_running = get_container_data(docker, DOCKER_MONGO_NAME)

    if not is_running:
        subprocess.check_output((docker, 'start', cont_id))

    mongo_port = get_container_service_port(docker, cont_id, '27017/tcp')
    fill_db_with_fixture(mongo_port, db_name, force=force_db_cleaning)

    atexit.register(stop_mongo)

    return mongo_port


def stop_mongo():
    docker = get_docker()
    cont_id, is_running = get_container_data(docker, DOCKER_MONGO_NAME)

    if is_running:
        logging.info('Stopping MongoDB')
        subprocess.check_output((docker, 'stop', cont_id))


def get_docker():
    return subprocess.check_output(('which', 'docker')).strip()


def get_container_data(docker, container_name):
    out = str(subprocess.check_output((docker, 'ps', '-a')).strip())
    lines = out.split(r'\n')

    cont_id = None
    is_running = None

    info_line = None
    for line in lines:
        if container_name in line:
            info_line = line
            break

    if not info_line:
        return cont_id, is_running

    cont_id, _ = info_line.strip().split(' ', 1)
    info = subprocess.check_output((docker, 'inspect', cont_id))

    info_data = json.loads(info)
    if not info_data:
        raise RuntimeError('Empty docker inspect info')

    is_running = info_data[0]['State']['Running']

    return cont_id, is_running


def get_container_service_port(docker, cont_id, internal_port):
    info = subprocess.check_output((docker, 'inspect', cont_id))

    info_data = json.loads(info)
    if not info_data:
        raise RuntimeError('Empty docker inspect info')

    port_data = info_data[0]['NetworkSettings']['Ports'].get(internal_port)
    if not port_data:
        raise RuntimeError(f'No port {internal_port} exposed')

    return port_data[0]['HostPort']


def fill_db_with_fixture(mongo_port, db_name, force=False):
    script_path = os.path.join(TEST_DATA_DIR, 'manage-db.py')

    call_args = [PYTHON, script_path, 'setup']
    if force:
        call_args.append('--force')

    subprocess.check_call(call_args, env={
        'MONGO_PORT': mongo_port,
        'MONGO_DB_NAME': db_name,
    })


def drop_db(db_name):
    logging.info('Drop DB %s', db_name)

    docker = get_docker()
    cont_id, is_running = get_container_data(docker, DOCKER_MONGO_NAME)
    if not is_running:
        raise RuntimeError('Mongo container is not running')

    mongo_port = get_container_service_port(docker, cont_id, '27017/tcp')
    script_path = os.path.join(TEST_DATA_DIR, 'manage-db.py')

    subprocess.check_call((PYTHON, script_path, 'tear-down'), env={
        'MONGO_PORT': mongo_port,
        'MONGO_DB_NAME': db_name,
    })


def get_csrf_token():
    token_file = os.path.join(TEST_DATA_DIR, 'test-csrf-token.txt')
    with open(token_file) as fp:
        return fp.read().strip()


def get_free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0', 0))
    return sock.getsockname()[1]

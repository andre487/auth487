# flake8: noqa F402
import logging
import os
import sys

sys.path.append(os.path.realpath(os.path.pardir))
import subprocess as sp

import app_common
import cli_tasks
from cli_tasks import common
from invoke import task

PROJECT_DIR = os.path.dirname(__file__)
TEST_AUTH_KEYS_DIR = os.path.join(PROJECT_DIR, 'test_data', 'auth_keys')
NEW_DATA_DIR = os.path.join(PROJECT_DIR, 'new_data')


@task
def start_docker(_c):
    """Run Docker via Colima"""
    sp.check_call(('colima', 'start', '--arch', 'x86_64'))


@task
def hash_password(_c, password):
    print(app_common.hash_password(password), end='')


@task
def generate_totp_secret(_c):
    import pyotp
    print(pyotp.random_base32(length=64), end='')


@task
def generate_auth_keys(c, t=False):
    data_dir = NEW_DATA_DIR
    if t:
        data_dir = TEST_AUTH_KEYS_DIR

    pr_key_file = os.path.join(data_dir, 'auth_key.pem')
    pub_key_file = os.path.join(data_dir, 'auth_key.pub.pem')

    for file_path in pr_key_file, pub_key_file:
        if os.path.exists(file_path):
            os.unlink(file_path)

    os.makedirs(data_dir, exist_ok=True)
    c.run(f'openssl ecparam -name secp521r1 -genkey -out {pr_key_file}')
    c.run(f'openssl ec -in {pr_key_file} -pubout -out {pub_key_file}')

    if t:
        test_auth_keys(c)


@task
def test_auth_keys(_c):
    from authlib.jose.rfc7517.asymmetric_key import load_pem_key

    with open(os.path.join(TEST_AUTH_KEYS_DIR, 'auth_key.pem'), 'rb') as fp:
        private_res = load_pem_key(fp.read(), key_type='private')
    print('Private key:')
    print(' curve name:', private_res.curve.name)
    print(' curve key size:', private_res.curve.key_size)

    with open(os.path.join(TEST_AUTH_KEYS_DIR, 'auth_key.pub.pem'), 'rb') as fp:
        pub_res = load_pem_key(fp.read(), key_type='public')
    print('Public key:')
    print(' curve name:', pub_res.curve.name)
    print(' curve key size:', pub_res.curve.key_size)


@task
def run_dev(c, port=5487, recreate_venv=False):
    """Run Flask dev server"""
    cli_tasks.run_dev.run(c, port, recreate_venv)


@task
def create_test_otp(c, user='test'):
    """Create one-time password for test users"""
    cli_tasks.create_test_otp.run(c, user)


@task
def create_prod_otp(c, user='test'):
    """Create one-time password for test users"""
    cli_tasks.prepare_secrets.run(c, recreate_venv=False)
    cli_tasks.create_prod_otp.run(c, user)


@task
def lint(c, recreate_venv=False):
    """Run flake8"""
    cli_tasks.run_linters.run(c, recreate_venv)


@task
def install(c, recreate_venv=False, packages=''):
    """Install packages: invoke install --packages='flask pytest'"""
    cli_tasks.install.run(c, recreate_venv, packages)


@task
def http_test(c, recreate_venv=False):
    """Run HTTP handlers test on dev instance"""
    cli_tasks.http_test.run(c, recreate_venv)


@task
def docker_build(c):
    """Build app Docker image"""
    cli_tasks.docker_build.run(c)


@task
def docker_push(c):
    """Push app Docker image to registry"""
    cli_tasks.docker_push.run(c)


@task
def docker_run(c, port=8181, rebuild=False):
    """Run app in Docker container"""
    if rebuild:
        cli_tasks.docker_build.run(c)
    cli_tasks.docker_run.run(c, port)


@task
def docker_test(c, recreate_venv=False, rebuild=False):
    """Run HTTP handlers test on Docker instance"""
    if rebuild:
        cli_tasks.docker_build.run(c)
    cli_tasks.docker_test.run(c, recreate_venv)


@task
def prepare_secrets(c, recreate_venv=False):
    """Prepare secrets for production"""
    cli_tasks.prepare_secrets.run(c, recreate_venv)


@task
def create_local_venv(c):
    """Prepare .venv dir for using in IDE"""
    common.prepare_virtual_env(c, recreate_venv=True)


@task
def make_deploy(c, recreate_venv=False, no_lint=False, no_test=False):
    """Deploy current work dir to production"""
    if not no_lint:
        cli_tasks.run_linters.run(c, recreate_venv)

    cli_tasks.prepare_secrets.run(c, recreate_venv)

    cli_tasks.docker_build.run(c)
    if not no_test:
        cli_tasks.docker_test.run(c, recreate_venv)
    cli_tasks.docker_push.run(c)

    c.run(f'ansible-playbook -v {common.PROJECT_DIR}/deploy/setup.yml', pty=True, env={
        'APP_DOCKER_IMAGE': common.DOCKER_IMAGE_NAME,
    })

    try:
        c.run('docker-clean')
    except Exception as e:
        logging.warning(e)

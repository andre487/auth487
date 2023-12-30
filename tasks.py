import os
import shutil
import sys
sys.path.append(os.path.realpath(os.path.pardir))
import subprocess as sp

import pyotp

import app_common
import cli_tasks
from cli_tasks import common
from invoke import task

PROJECT_DIR = os.path.dirname(__file__)
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
    print(pyotp.random_base32(length=64), end='')


@task
def generate_auth_keys(c):
    os.makedirs(NEW_DATA_DIR, exist_ok=True)
    key_file_path = os.path.join(NEW_DATA_DIR, 'auth_key.pem')
    c.run(f'ssh-keygen -t rsa -b 4096 -m PEM -f {key_file_path}')

    origin_pub_key_file = f'{key_file_path}.pub'
    correct_pub_key_file = origin_pub_key_file.replace('.pem.pub', '.pub.pem')
    shutil.move(origin_pub_key_file, correct_pub_key_file)


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
    cli_tasks.prepare_secrets.run(c, recreate_venv=False, no_secret_cache=False, silent=True)
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
def docker_run(c, port=8181):
    """Run app in Docker container"""
    cli_tasks.docker_run.run(c, port)


@task
def docker_test(c, recreate_venv=False):
    """Run HTTP handlers test on Docker instance"""
    cli_tasks.docker_test.run(c, recreate_venv)


@task
def prepare_secrets(c, recreate_venv=False, no_secret_cache=False):
    """Prepare secrets for production"""
    cli_tasks.prepare_secrets.run(c, recreate_venv, no_secret_cache)


@task
def create_local_venv(c, rebuild_venv=False):
    """Prepare .venv dir for using in IDE"""
    common.prepare_virtual_env(c, rebuild_venv)


@task
def make_deploy(c, recreate_venv=False, no_secret_cache=False):
    """Deploy current work dir to production"""
    cli_tasks.run_linters.run(c, recreate_venv)

    cli_tasks.prepare_secrets.run(c, recreate_venv, no_secret_cache)

    cli_tasks.docker_build.run(c)
    cli_tasks.docker_test.run(c, recreate_venv)
    cli_tasks.docker_push.run(c)

    c.run(
        f'ansible-playbook '
        f'{common.PROJECT_DIR}/deploy/setup.yml'
    )

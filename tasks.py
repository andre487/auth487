import os
import cli_tasks
from cli_tasks import common
from invoke import task


@task
def run_dev(c, port=8080, recreate_venv=False):
    """Run Flask dev server"""
    cli_tasks.run_dev.run(c, port, recreate_venv)


@task
def lint(c, recreate_venv=False):
    """Run flake8"""
    cli_tasks.run_linters.run(c, recreate_venv)


@task
def install(c, recreate_venv=False, packages=''):
    """Install packages: invoke install --packages='flask pytest'"""
    cli_tasks.install.run(c, recreate_venv, packages)


@task
def freeze(c, recreate_venv=False):
    """Freeze requirements.txt"""
    cli_tasks.freeze_requirements.run(c, recreate_venv)


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
def make_deploy(c, recreate_venv=False):
    """Deploy current work dir to production"""
    cli_tasks.run_linters.run(c, recreate_venv)

    cli_tasks.docker_build.run(c)
    cli_tasks.docker_test.run(c, recreate_venv)
    cli_tasks.docker_push.run(c)

    c.run(
        f'ansible-playbook '
        f'--inventory {os.getenv("HOME")}/work/ansible-inventory/ansible-inventory.yml '
        f'{common.PROJECT_DIR}/deploy/setup.yml'
    )
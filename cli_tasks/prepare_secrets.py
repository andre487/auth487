import os
from . import common

def run(c, recreate_venv):
    common.prepare_virtual_env(c, recreate_venv)

    python_bin_path = os.path.join(common.VENV_DIR, 'bin', 'python3')
    script_path = os.path.join(common.PROJECT_DIR, 'yc_secret_fetcher.py')

    c.run(f'{python_bin_path} {script_path} once --dev-run --secrets-dir "{common.SECRET_DIR}"')

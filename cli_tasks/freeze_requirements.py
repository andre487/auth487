import os
import re
from . import common


def run(c, recreate_venv):
    common.prepare_virtual_env(c, recreate_venv)
    c.run(f'{common.PYTHON} -m pip freeze > {common.PROJECT_DIR}/requirements.txt')

    code_parts = []
    with open(f'{common.PROJECT_DIR}/requirements.txt') as fp:
        for req in fp.readlines():
            if not req or req.startswith('#'):
                continue

            code_parts.append(f"'{req.strip()}'")

    req_text = ', '.join(code_parts)

    lib_setup_file = os.path.join(os.path.dirname(__file__), '..', 'lib', 'setup.py')
    with open(lib_setup_file) as fp:
        content = re.sub(r'(requirements\s*=\s*\[).+(].*)', rf'\1{req_text}\2', fp.read())

    with open(lib_setup_file, 'w') as fp:
        fp.write(content)

    print('OK')

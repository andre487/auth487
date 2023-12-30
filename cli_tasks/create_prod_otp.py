import json
import os

PROJECT_DIR = os.path.join(os.path.dirname(__file__), os.path.pardir)


def run(c, user):
    import pyotp

    auth_file = os.path.join(PROJECT_DIR, '.secret', 'auth_info', 'auth_info.json')
    with open(auth_file) as fp:
        auth_data = json.load(fp)

    user_data = auth_data.get(user)
    if not user_data:
        raise Exception(f'There is no user `{user}`')

    print('OTP:', pyotp.TOTP(user_data['totp_secret']).now())

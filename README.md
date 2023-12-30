# auth487
JWT auth system

## How to start

```shell
cd "$DATA_API_DIR"
python3 -m pip install invoke
python3 -m invoke --list
```

## How to test email

[How to set up Gmail](https://medium.com/lyfepedia/sending-emails-with-gmail-api-and-python-49474e32c81f)

```shell
export NOTIFICATION_EMAIL_FROM=from@example.com
export NOTIFICATION_EMAIL_TO=to@example.com
export GMAIL_CREDENTIALS_FILE=/path/to/service/account/credentials.json

python3 -m invoke run-dev
```

## Test auth

Password: `test`
TOTP: `./.venv/bin/python3 -m invoke create-test-otp [--user USER]`

## Build in Docker

```
  $ brew install colima docker
  $ colima start --arch x86_64
  $ docker ps
```

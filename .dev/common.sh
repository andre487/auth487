#@IgnoreInspection BashAddShebang
cur_dir="$(cd "$(dirname "$0")" && pwd)"
dev_env="$HOME/.venv/auth487"

export AUTH_PRIVATE_KEY_FILE="$HOME/.private/auth487/private_key.pem"
export AUTH_PUBLIC_KEY_FILE="$HOME/.private/auth487/public_key.pem"
export AUTH_INFO_FILE="$cur_dir/.dev/test-auth-info.json"

export FLASK_APP=app.py
export FLASK_ENV=dev
export FLASK_DEBUG=1

export DEV_PORT=5487
export TEST_PORT=5489

export AUTH_MONGO_DB_NAME=auth487_test

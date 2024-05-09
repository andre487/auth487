#!/usr/bin/env bash
set -eufxo pipefail
cd "$(dirname "$0")"

export PYTHONDONTWRITEBYTECODE=1

if [[ -z "${SECRETS_DIR:-}" ]]; then
    echo "No secret dir"
    exit 1
fi

YC_SECRET_RUN_ARG=''
if [[ "${SECRETS_DEV_RUN:-}" == 1 ]]; then
    YC_SECRET_RUN_ARG=--dev-run
fi
export YC_SECRET_RUN_ARG

./yc_secret_fetcher.py once --secrets-dir "$SECRETS_DIR" "${YC_SECRET_RUN_ARG[@]}"

supervisord --configuration conf/supervisord.conf

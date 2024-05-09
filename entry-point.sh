#!/usr/bin/env bash
set -exo pipefail

proj_dir="$(cd "$(dirname "$0")" && pwd)"
cd "$proj_dir"

cpu_count="$(getconf _NPROCESSORS_ONLN)"
worker_count="$((cpu_count * 2))"

if [[ -z "$SECRETS_DIR" ]]; then
    echo "No secret dir"
    exit 1
fi

run_arg=()
if [[ "$SECRETS_DEV_RUN" == 1 ]]; then
    run_arg=(--dev-run)
fi

./yc_secret_fetcher.py once --secrets-dir "$SECRETS_DIR" "${run_arg[@]}"

uwsgi --http '0.0.0.0:5000' \
    --workers "$worker_count" \
    --master \
    --disable-logging \
    --no-orphans \
    --wsgi-file app.py \
    --callable app \
    --die-on-term \
    --static-map /static="$proj_dir/static"

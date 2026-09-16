#!/bin/sh
set -e

# 바인드 마운트된 데이터 볼륨은 호스트 쪽 소유권을 그대로 가져오므로, 매 시작마다
# 전용 실행 계정이 쓸 수 있도록 소유권을 맞춘 뒤 root 권한을 내려놓고 앱을 실행한다.
mkdir -p "${CF_DATA_DIR:-/app/data}"
chown -R appuser:appuser "${CF_DATA_DIR:-/app/data}"

# worker 1개 + 스레드로만 동시성을 처리한다: SQLite는 다중 프로세스 동시 쓰기에 취약하고
# (database is locked), 레이트리밋(in-memory)도 프로세스마다 카운터가 분리되면 우회당하기
# 쉬워지므로, 여러 워커 프로세스로 나누지 않는다.
exec gosu appuser gunicorn \
    --worker-class gthread \
    --workers 1 \
    --threads 4 \
    --bind "0.0.0.0:${PORT:-8000}" \
    --access-logfile - \
    --error-logfile - \
    wsgi:app

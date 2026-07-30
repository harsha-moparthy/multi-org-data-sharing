#!/usr/bin/env bash
# Project-local Postgres without Docker (macOS, Homebrew postgresql@16).
# Data lives in ./pgdata inside the repo; server listens on 127.0.0.1:5435.
# Port 5435 rather than the default 5432 so this coexists with any local Postgres.
# Usage: scripts/pg_local.sh {start|stop|status|init|reset|psql}
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PGDATA="$REPO_ROOT/pgdata"
PGBIN="$(brew --prefix postgresql@16)/bin"
PORT=5435
DBNAME=sharing
# The bootstrap superuser. The application never connects as this role — see
# schema.sql: the app connects as `portal_app`, which holds no direct table
# privileges, so a query that escapes the guarded views fails at Postgres.
DBUSER=shareadmin
LOG="$PGDATA/server.log"

init() {
  if [ -d "$PGDATA" ]; then
    echo "pgdata already exists at $PGDATA"
    return 0
  fi
  "$PGBIN/initdb" -D "$PGDATA" -U "$DBUSER" --auth=trust >/dev/null
  echo "initialized $PGDATA"
}

start() {
  init
  if "$PGBIN/pg_ctl" -D "$PGDATA" status >/dev/null 2>&1; then
    echo "already running"
  else
    "$PGBIN/pg_ctl" -D "$PGDATA" -l "$LOG" -o "-p $PORT -c listen_addresses=127.0.0.1" start
  fi
  "$PGBIN/psql" -h 127.0.0.1 -p "$PORT" -U "$DBUSER" -d postgres -tc \
    "SELECT 1 FROM pg_database WHERE datname='$DBNAME'" | grep -q 1 || \
    "$PGBIN/createdb" -h 127.0.0.1 -p "$PORT" -U "$DBUSER" "$DBNAME"
  echo "postgres ready on 127.0.0.1:$PORT (db: $DBNAME)"
}

stop() { "$PGBIN/pg_ctl" -D "$PGDATA" stop -m fast; }
status() { "$PGBIN/pg_ctl" -D "$PGDATA" status; }

# Drop and recreate the application database (keeps the cluster).
reset() {
  "$PGBIN/dropdb" -h 127.0.0.1 -p "$PORT" -U "$DBUSER" --if-exists "$DBNAME"
  "$PGBIN/createdb" -h 127.0.0.1 -p "$PORT" -U "$DBUSER" "$DBNAME"
  echo "database $DBNAME recreated"
}

psql_() { exec "$PGBIN/psql" -h 127.0.0.1 -p "$PORT" -U "$DBUSER" -d "$DBNAME" "$@"; }

case "${1:-start}" in
  start) start ;;
  stop) stop ;;
  status) status ;;
  init) init ;;
  reset) reset ;;
  psql) shift; psql_ "$@" ;;
  *) echo "usage: $0 {start|stop|status|init|reset|psql}"; exit 1 ;;
esac

#!/bin/bash
# Proxy user management helper
# Usage:
#   ./scripts/manage-proxy-users.sh add <username>       — add or update user
#   ./scripts/manage-proxy-users.sh delete <username>    — remove user
#   ./scripts/manage-proxy-users.sh list                 — list usernames
#
# The passwd file is stored at ./squid-auth/passwd and mounted into the
# Squid container at /etc/squid/auth/passwd.
# Changes take effect immediately (Squid re-reads the file on each auth request).
#
# htpasswd runs inside the squid container (apache2-utils is installed there).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASSWD_HOST="$PROJECT_DIR/squid-auth/passwd"
PASSWD_CONTAINER="/etc/squid/auth/passwd"

mkdir -p "$PROJECT_DIR/squid-auth"

# Run htpasswd inside the squid container where apache2-utils is installed.
# The passwd file is bind-mounted so writes are reflected on the host immediately.
htpasswd_in_container() {
    docker compose -f "$PROJECT_DIR/docker-compose.yml" exec -T squid htpasswd "$@"
}

case "${1:-}" in
  add)
    username="${2:?Usage: $0 add <username>}"
    # Create file on first use so the container doesn't receive a -c flag that
    # would truncate an existing file when the file already exists on host.
    if [ -f "$PASSWD_HOST" ] && grep -q "^${username}:" "$PASSWD_HOST" 2>/dev/null; then
      echo "Updating password for existing user: $username"
      htpasswd_in_container "$PASSWD_CONTAINER" "$username"
    elif [ -f "$PASSWD_HOST" ] && [ -s "$PASSWD_HOST" ]; then
      echo "Adding new user: $username"
      htpasswd_in_container "$PASSWD_CONTAINER" "$username"
    else
      echo "Adding first user: $username (creating passwd file)"
      htpasswd_in_container -c "$PASSWD_CONTAINER" "$username"
    fi
    echo "Done. Proxy auth will pick up the change immediately."
    ;;

  delete)
    username="${2:?Usage: $0 delete <username>}"
    if [ ! -f "$PASSWD_HOST" ]; then
      echo "passwd file not found: $PASSWD_HOST"
      exit 1
    fi
    htpasswd_in_container -D "$PASSWD_CONTAINER" "$username"
    echo "User '$username' removed."
    ;;

  list)
    if [ ! -f "$PASSWD_HOST" ] || [ ! -s "$PASSWD_HOST" ]; then
      echo "(no users configured)"
    else
      echo "Configured proxy users:"
      cut -d: -f1 "$PASSWD_HOST"
    fi
    ;;

  *)
    echo "Usage: $0 {add|delete|list} [username]"
    exit 1
    ;;
esac

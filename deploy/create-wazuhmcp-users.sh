#!/usr/bin/env bash
# Create least-privilege `wazuhmcp` users on the Wazuh server (run it ON the Wazuh host).
#   sudo bash create-wazuhmcp-users.sh
# Asks for the current admin credentials (indexer `admin`, API `wazuh-wui`) and prints
# the new passwords once: put them in /etc/wazuhmcp/wazuhmcp.env as
# WAZUHMCP_INDEXER_PASSWORD and WAZUHMCP_API_PASSWORD (users are both "wazuhmcp").
#
# Indexer role: search only, on the two index patterns WazuhMCP reads.
# API role    : read agents/packages + run active-response, restart agent, FIM scan.
#               No manager:read on purpose: it exposes ossec.conf (integration secrets).
# Re-running fails on "already exists": delete the user/role/policy first.
set -euo pipefail
NAME="${WAZUHMCP_USER:-wazuhmcp}"
IDX="${INDEXER_URL:-https://127.0.0.1:9200}"
API="${API_URL:-https://127.0.0.1:55000}"
K=(-sk --fail-with-body)   # loopback on the Wazuh host itself; certs don't name 127.0.0.1 for the API

# Passwords meet Wazuh's policy: upper, lower, digit, symbol, >= 8 chars.
genpw() { echo "Wm$(openssl rand -hex 16)!a"; }

read -rp  "Indexer admin user [admin]: " IU; IU="${IU:-admin}"
read -rsp "Indexer admin password: " IP; echo
read -rp  "API admin user [wazuh-wui]: " AU; AU="${AU:-wazuh-wui}"
read -rsp "API admin password: " AP; echo

# ---------------- Indexer (OpenSearch security plugin) ----------------
IDX_PW="$(genpw)"
ix() { curl "${K[@]}" -u "$IU:$IP" -H 'Content-Type: application/json' -X PUT "$IDX/_plugins/_security/api/$1" -d "$2"; echo; }
ix "roles/${NAME}_read" '{
  "cluster_permissions": ["cluster_composite_ops_ro"],
  "index_permissions": [{
    "index_patterns": ["wazuh-alerts-4.x-*", "wazuh-states-vulnerabilities-*"],
    "allowed_actions": ["read"]
  }]
}'
ix "internalusers/$NAME" "{\"password\": \"$IDX_PW\"}"
ix "rolesmapping/${NAME}_read" "{\"users\": [\"$NAME\"]}"

# ---------------- Wazuh API (RBAC) ----------------
API_PW="$(genpw)"
TOKEN="$(curl "${K[@]}" -u "$AU:$AP" -X POST "$API/security/user/authenticate?raw=true")"
api() { curl "${K[@]}" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -X POST "$API$1" ${2:+-d "$2"}; }
id_of() { sed -n 's/.*"affected_items": *\[ *{ *"id": *\([0-9]*\).*/\1/p'; }

USER_ID="$(api /security/users "{\"username\": \"$NAME\", \"password\": \"$API_PW\"}" | id_of)"
ROLE_ID="$(api /security/roles "{\"name\": \"$NAME\"}" | id_of)"
POLICY_IDS=()
policy() {  # name, actions(json), resources(json)
  POLICY_IDS+=("$(api /security/policies "{\"name\": \"${NAME}_$1\", \"policy\": {\"actions\": $2, \"resources\": $3, \"effect\": \"allow\"}}" | id_of)")
}
policy agents   '["agent:read", "agent:restart", "syscollector:read", "syscheck:run", "active-response:command"]' '["agent:id:*"]'
for p in "${POLICY_IDS[@]}"; do
  [ -n "$p" ] || { echo "policy creation failed" >&2; exit 1; }
done
[ -n "$USER_ID" ] && [ -n "$ROLE_ID" ] || { echo "user/role creation failed" >&2; exit 1; }
api "/security/roles/$ROLE_ID/policies?policy_ids=$(IFS=,; echo "${POLICY_IDS[*]}")" >/dev/null
api "/security/users/$USER_ID/roles?role_ids=$ROLE_ID" >/dev/null

# ---------------- Check ----------------
curl "${K[@]}" -o /dev/null -u "$NAME:$IDX_PW" "$IDX/wazuh-alerts-4.x-*/_search?size=0" && echo "indexer login ok"
curl "${K[@]}" -o /dev/null -u "$NAME:$API_PW" -X POST "$API/security/user/authenticate" && echo "api login ok"

cat <<EOF

Created user "$NAME". Save these now, they are not stored anywhere:
  indexer password (WAZUHMCP_INDEXER_PASSWORD): $IDX_PW
  api password     (WAZUHMCP_API_PASSWORD)    : $API_PW
EOF

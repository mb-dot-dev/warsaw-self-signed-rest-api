#!/usr/bin/env bash
# Call the deployed warsaw API end to end: sign a client assertion, exchange it for an
# access token, then POST a JSON body to the producer endpoint.
#
#   scripts/call_api.sh '{"hello": "world"}'
#
# The client private key is read from 1Password and never touches disk. The API URL and
# client id are looked up from AWS unless WARSAW_API_URL / WARSAW_CLIENT_ID are set.
#
# Requires: op (signed in), openssl, curl, jq, and aws when the overrides are unset.

set -euo pipefail

DEFAULT_BODY='{"hello": "world"}'
BODY="${1:-$DEFAULT_BODY}"
OP_KEY_REF="${WARSAW_OP_KEY_REF:-warsaw client private key}"
OP_VAULT="${WARSAW_OP_VAULT:-Private}"
AUDIENCE="https://auth.molnarbence.dev/"
ASSERTION_TTL_SECONDS=60

API_URL="${WARSAW_API_URL:-$(aws cloudformation describe-stacks --stack-name warsaw-lambda \
  --query 'Stacks[0].Outputs[?OutputKey==`ApiGatewayUrl`].OutputValue' --output text)}"
API_URL="${API_URL%/}/"
CLIENT_ID="${WARSAW_CLIENT_ID:-$(aws ssm get-parameter --name /projects/warsaw/allowed-client-id \
  --query Parameter.Value --output text)}"

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

now=$(date +%s)
header=$(jq -cn '{alg: "RS256", typ: "JWT"}' | b64url)
claims=$(jq -cn \
  --arg client_id "$CLIENT_ID" \
  --arg aud "$AUDIENCE" \
  --arg jti "$(uuidgen)" \
  --argjson iat "$now" \
  --argjson exp "$((now + ASSERTION_TTL_SECONDS))" \
  '{iss: $client_id, sub: $client_id, aud: $aud, iat: $iat, exp: $exp, jti: $jti}' | b64url)
signing_input="${header}.${claims}"
signature=$(printf '%s' "$signing_input" \
  | openssl dgst -sha256 -sign <(op document get "$OP_KEY_REF" --vault "$OP_VAULT") \
  | b64url)
assertion="${signing_input}.${signature}"

access_token=$(curl -sS --fail-with-body -X POST "${API_URL}oauth/token" \
  -d grant_type=client_credentials \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion="$assertion" | jq -r .access_token)

curl -sS --fail-with-body -X POST "$API_URL" \
  -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" \
  -d "$BODY"
echo

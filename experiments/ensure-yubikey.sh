#!/usr/bin/env bash

set -euo pipefail

serial="$1"
slot="$2"
validity_period="$3"

common_args=(
  -v
  -s "$slot"
)

auth_args=(
  --key=REDACTED
)

generate_args=(
  -A ECCP384
  --touch-policy=never --pin-policy=never
)

selfsign_args=(
  -H SHA384
  -S '/C=US/ST=California/L=Carlsbad/O=nixpkcs/OU=Keymaster/CN=nixpkcs Root CA/'
  --valid-days=$((365 * 2))
  --attestation
)

import_args=(
  --compress
)

# Writes a log message.
log() {
  echo "[nixpkcs] $*" >&2
}

# Reads a certificate from the token.
_CERT=''
read_cert() {
  local cert

  log "Reading cert with arguments: ${common_args[*]}"
  set +e
  cert="$(yubico-piv-tool -a read-certificate "${common_args[@]}")"
  result=$?
  set -e

  _CERT=''
  if [ $result -eq 0 ]; then
    log "Read certificate successfully."
    _CERT="$cert"
  else
    log "Certificate read failed: $result"
  fi
}

# Generates a key.
gen_key() {
  local pubkey certificate
  
  log "Generating key with arguments: ${common_args[*]} ${generate_args[*]}"
  yubico-piv-tool -a generate "${common_args[@]}" "${generate_args[@]}" "${auth_args[@]}" >/dev/null

  log "Self signing certificate with arguments: ${selfsign_args[*]}"
  certificate="$(yubico-piv-tool -a selfsign-certificate "${common_args[@]}" "${selfsign_args[@]}" "${auth_args[@]}")"

  log "Importing certificate with arguments: ${import_args[*]}"
  echo "$certificate" | yubico-piv-tool -a import-certificate "${common_args[@]}" "${import_args[@]}" "${auth_args[@]}"
}

# Returns 0 if the cert is expiring or expired.
# @param $1 the cert
# @param $2 the validity_period in days
is_expiring() {
  local cert="$1"
  local validity_period="$2"
  local now not_after cutoff
  validity_period=$((validity_period * 86400))
  now="$(date +%s)"
  not_after="$(echo "$cert" | openssl x509 -noout -enddate | head -n1 | cut -d= -f2 | tr '\n' '\0' | xargs -0 -I {} date -d '{}' +%s)"
  cutoff=$((not_after - validity_period))

  log "Now:       $(date -I -d "@$now")"
  log "Not after: $(date -I -d "@$not_after")"
  log "Renews at: $(date -I -d "@$((cutoff+1))")"

  if [ "$now" -gt "$cutoff" ]; then
    return 0
  else
    return 1
  fi
}

get_readers
reader="${_SERIAL_TO_READER["$serial"]:-}"
if [ -z "$reader" ]; then
  log "Reader with serial $serial is not connected"
else
  common_args+=(-r "$reader")
fi

read_cert

if [ -z "$_CERT" ] || is_expiring "$_CERT" "$validity_period"; then
  gen_key
  read_cert
  is_expiring "$_CERT" "$validity_period" || true
fi

echo "$_CERT"
exit 0

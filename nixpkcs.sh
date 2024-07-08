#!/usr/bin/env bash

set -euo pipefail
shopt -s extglob

script_name="$(basename -- "${BASH_SOURCE[0]:-$0}")"
label='unknown key'

echo -n "$script_name" > "/proc/$$/comm" 2>/dev/null || true

debug=0
if [[ -v NIXPKCS_DEBUG ]] && [ -n "$NIXPKCS_DEBUG" ] && [ "$NIXPKCS_DEBUG" != '0' ]; then
  debug=1
fi

# Writes a log message.
log() {
  local level="$1"
  shift
  echo "[$script_name/$level] ($label) $*" >&2
}

# Writes a debug message.
debug() {
  if [ $debug -ne 0 ]; then
    log 'D' "$@"
  fi
}

# Writes an info message.
info() {
  log 'I' "$@"
}

# Writes a warning message.
warn() {
  log 'W' "$@"
}

# Writes an error message.
error() {
  log 'E' "$@"
}

# Verify that the key name was passed.
if [ $# -lt 1 ]; then
  error "Usage: $0 <key name>"
  exit 1
else
  label="$1"
fi

if [[ ! -v NIXPKCS_KEY_SPEC ]] || [ -z "$NIXPKCS_KEY_SPEC" ]; then
  error "NIXPKCS_KEY_SPEC was not set"
  exit 1
fi

# Sanitizes the secret in $1, setting '_SECRET'.
# Deletes all non-alphanumerics, _, and -.
_SECRET=''
sanitize_secret() {
  local secret="$1"
  _SECRET="${secret//[^0-9A-Za-z_-]/}"
}

# Executes a command, logging it and redacting secrets.
# Usage: log_exec (secrets) -- (command)
log_exec() (
  local secrets=()
  local args=()
  local log_args=()
  local reading_args=0

  for arg in "$@"; do
    if [ $reading_args -eq 0 ]; then
      case "$arg" in
        --)
          reading_args=1
          ;;
        *)
          sanitize_secret "$arg"
          arg="$_SECRET"
          if [ -n "$arg" ]; then
            secrets+=("$arg")
          fi
          ;;
      esac
    else
      args+=("$arg")

      # Strip secrets from the logs.
      for secret in ${secrets[@]+"${secrets[@]}"}; do
        arg="${arg//$secret/\/\/REDACTED\/\/}"
      done
      log_args+=("$arg")
    fi
  done

  info "<exec> $(printf '%q ' "${log_args[@]+"${log_args[@]}"}")"
  exec ${args[@]+"${args[@]}"}
)

# Runs pkcs11-tool.
# $1: The operation mode (anonymous|user|so).
# $@: The remaining pkcs11-tool args.
p11tool() {
  local op_mode="$1"
  shift

  local args=(--token-label "$token" --id "$id" --label "$label")
  local secrets=()
  case "$op_mode" in
    anonymous)
      ;;
    user)
      if [ -n "$key_options_pin" ]; then
        args+=(--login --login-type user --pin "$key_options_pin")
        secrets+=("$key_options_pin")
      fi
      ;;
    so)
      if [ -n "$key_options_so_pin" ]; then
        if [ "$key_options_login_as_user" == 'true' ]; then
          # Don't use the Security Officer login even though we ordinarily would.
          args+=(--login --login-type user --pin "$key_options_so_pin")
        else
          args+=(--login --login-type so --so-pin "$key_options_so_pin")
        fi
        secrets+=("$key_options_so_pin")
      fi
      ;;
    *)
      error "Invalid operation mode: $op_mode"
      return 1
      ;;
  esac

  log_exec ${secrets[@]+"${secrets[@]}"} -- pkcs11-tool ${args[@]+"${args[@]}"} "$@"
}

# Runs OpenSSL, stripping secrets out of the log.
ossl() {
  log_exec "$key_options_pin" "$key_options_so_pin" -- openssl "$@"
}

# Reads a certificate from the yubikey.
_CERT=''
read_cert() {
  info "Available slots"
  p11tool anonymous --list-slots

  info "Reading certificate"
  local cert
  set +e
  cert="$(p11tool anonymous --read-object --type cert | openssl x509 -inform der)"
  result=$?
  set -e

  _CERT=''
  if [ $result -eq 0 ]; then
    info "Read certificate successfully."
    _CERT="$cert"
  else
    error "Certificate read failed: $result"
  fi
}

# Generates a key.
gen_key() {
  info "Available slots"
  p11tool anonymous --list-slots

  info "Generating key"
  local usages=()
  for usage in sign derive decrypt wrap; do
    if [[ -v key_options_usage["$usage"] ]]; then
      usages+=("--usage-$usage")
    fi
  done
  p11tool so --keypairgen --key-type "${key_options_algorithm}:${key_options_type}" ${usages[@]+"${usages[@]}"}

  info "Self signing certificate"
  local args=()
  if [ -n "$cert_options_serial" ]; then
    args+=(-set_serial "0x$cert_options_serial")
  fi

  for ext in ${cert_options_extensions[@]+"${cert_options_extensions[@]}"}; do
    if [[ "$ext" = *=* ]]; then
      # These are key/value pairs.
      args+=(-addext "$ext")
    else
      # These are not (e.g. v3_ca).
      args+=(-extensions "$ext")
    fi
  done

  local certificate
  certificate="$(ossl req -provider pkcs11 -key "$uri" -new -x509 "-$cert_options_digest" \
    -subj "/$cert_options_subject" \
    -days "$cert_options_validity_days" ${args[@]+"${args[@]}"} -outform PEM)"

  info "Importing certificate"
  echo "$certificate" | openssl x509 -inform pem -outform der | p11tool so --write-object /dev/stdin --type cert
}

# Returns 0 if the cert is expiring or expired.
# @param $1 the cert
# @param $2 the renewal period in days
is_expiring() {
  local cert="$1"
  local renewal_period="$2"
  local now not_after cutoff

  if [ "$renewal_period" -lt 0 ]; then
    warn "Certificate renewal checking is disabled."
    return 1
  fi

  renewal_period=$((renewal_period * 86400))
  now="$(date +%s)"
  not_after="$(echo "$cert" | openssl x509 -noout -enddate | head -n1 | cut -d= -f2 | tr '\n' '\0' | xargs -0I{} date -d '{}' +%s)"
  cutoff=$((not_after - renewal_period))

  info "Now:       $(date -I -d "@$now")"
  info "Not after: $(date -I -d "@$not_after")"
  info "Renews at: $(date -I -d "@$((cutoff+1))")"

  if [ "$now" -gt "$cutoff" ]; then
    return 0
  else
    return 1
  fi
}

# Runs the rekey hook if it exists with the specified arguments.
_REKEY_STATUS=0
run_rekey_hook() {
  _REKEY_STATUS=0
  if [ -n "$cert_options_rekey_hook" ] && [ -x "$cert_options_rekey_hook" ]; then
    info "Running rekey hook: $cert_options_rekey_hook"
    set +e
    echo "$_CERT" | "$cert_options_rekey_hook" "$@"
    _REKEY_STATUS=$?
    set -e
  fi
}

info "Starting."

# Make sure we have the list of params we're reading ahead of time.
declare token id uri \
  key_options_algorithm key_options_type key_options_so_pin_file key_options_force key_options_login_as_user \
  cert_options_digest cert_options_serial cert_options_subject \
  cert_options_validity_days cert_options_renewal_period cert_options_pin_file cert_options_rekey_hook

vars=(token id uri
  key_options_algorithm key_options_type key_options_so_pin_file key_options_force key_options_login_as_user
  cert_options_digest cert_options_serial cert_options_subject
  cert_options_validity_days cert_options_renewal_period cert_options_pin_file cert_options_rekey_hook
)

{
  # Read them from jq.
  for var in ${vars[@]+"${vars[@]}"}; do
    IFS= read -r "${var?}"
    debug "$var=${!var}"
  done

  # Check the required params.
  for required_param in "$token" "$id" "$uri" \
    "$key_options_algorithm" "$key_options_type" \
    "$cert_options_digest" "$cert_options_subject" \
    "$cert_options_validity_days" "$cert_options_renewal_period"; do
    if [ -z "$required_param" ]; then
      error "Required parameter missing"
      exit 1
    fi
  done

  # Validate the algorithm and type.
  key_options_algorithm="$(echo "$key_options_algorithm" | tr '[:lower:]' '[:upper:]')"
  key_options_type="$(echo "$key_options_type" | tr '[:upper:]' '[:lower:]')"
  case "$key_options_algorithm" in
    RSA)
      case "$key_options_type" in
        2048|3072|4096)
          ;;
        *)
          error "Invalid RSA bits: $key_options_type"
          exit 1
          ;;
      esac
      ;;
    EC)
      case "$key_options_type" in
        secp256r1|prime256r1|secp384r1|secp521r1)
          ;;
        ed25519|curve25519)
          ;;
        *)
          error "Invalid EC curve: $key_options_type"
          exit 1
          ;;
      esac
      ;;
    *)
      error "Invalid key algorithm: $key_options_algorithm"
      exit 1
      ;;
  esac

  # Validate the digest against those allowed by openssl.
  cert_options_digest="$(echo "$cert_options_digest" | tr '[:upper:]' '[:lower:]')"
  if ! { openssl list -1 --digest-commands | grep -q "$cert_options_digest"; }; then
    error "Invalid digest: $cert_options_digest. Use 'openssl list --digest-commands' for a list."
    exit 1
  fi
 
  # Read the pin file(s).
  pins=()
  for pin_file in "$key_options_so_pin_file" "$cert_options_pin_file"; do
    if [ -n "$pin_file" ]; then
      if [ -f "$pin_file" ]; then
        sanitize_secret "$(<"$pin_file")"
        if [ -n "$_SECRET" ]; then
          pins+=("$_SECRET")
        else
          error "PIN file '$pin_file' didn't appear to contain a PIN"
          exit 1
        fi
      else
        error "PIN file '$pin_file' was specified and didn't exist"
        exit 1
      fi
    else
      pins+=('')
    fi
  done

  key_options_so_pin="${pins[0]}"
  key_options_pin="${pins[1]}"
} < <(
  # Ensure that these are ordered the same as above.
  echo "$NIXPKCS_KEY_SPEC" | \
    jq --arg expectedLength "${#vars[@]}" -r '
      def unpack_exact_n($arr; $length):
        if ($arr | length) == $length then $arr | .[]
        else error("invalid length, expected " + ($length | tostring) + " but got " + ($arr | length | tostring))
        end;
      unpack_exact_n([
        .token? // "", .id? // 0, .uri? // "",
        .keyOptions?.algorithm? // "", .keyOptions?.type? // "", .keyOptions?.soPinFile? // "", .keyOptions?.force // false, .keyOptions?.loginAsUser // false,
        .certOptions?.digest? // "SHA256", .certOptions?.serial? // "", .certOptions.subject? // "",
        .certOptions?.validityDays? // 0,
        .certOptions?.renewalPeriod? // 0, .certOptions?.pinFile? // "", .certOptions?.rekeyHook? // ""
      ]; $expectedLength | tonumber)
    '
)

# Read the key usage.
declare -a key_options_usage_arr
declare -A key_options_usage
{ mapfile -t key_options_usage_arr; } < <(
  echo "$NIXPKCS_KEY_SPEC" | \
    jq -r '(.keyOptions?.usage? // []).[]'
)
for usage in ${key_options_usage_arr[@]+"${key_options_usage_arr[@]}"}; do
  key_options_usage["$usage"]=1
done
debug "key_options_usage=${!key_options_usage[*]}"

# Read the extensions.
declare -a cert_options_extensions
{ mapfile -t cert_options_extensions; 
  debug "cert_options_extensions=${cert_options_extensions[*]}"
} < <(
  echo "$NIXPKCS_KEY_SPEC" | \
    jq -r '(.certOptions?.extensions? // []).[]'
)

# Read the certificate and run the rekey hook with the old cert.
rekey_status=0
if [ "$key_options_force" != 'true' ]; then
  read_cert
  if [ -n "$_CERT" ]; then
    echo "$_CERT" | run_rekey_hook old

    if [ $_REKEY_STATUS -ne 0 ]; then
      warn "Rekey hook returned $_REKEY_STATUS; skipping rekey."
    fi
  fi
fi

# Check if we need to regenerate the key.
if [ $rekey_status -eq 0 ] && { [ -z "$_CERT" ] || is_expiring "$_CERT" "$cert_options_renewal_period"; }; then
  gen_key
  read_cert
  if is_expiring "$_CERT" "$cert_options_renewal_period"; then
    warn "Generated a cert that's about to expire!"
  fi

  echo "$_CERT" | run_rekey_hook new

  if [ $_REKEY_STATUS -ne 0 ]; then
    warn "Rekey hook returned $_REKEY_STATUS."
  fi
fi

echo "$_CERT"
exit 0

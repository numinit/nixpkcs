#!/usr/bin/env bash

set -euo pipefail
shopt -s extglob

script_path="${BASH_SOURCE[0]:-$0}"
script_name="$(basename -- "$script_path")"
label='unknown key'

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

# Cleans up the temp directory.
_TEMPDIR=''
_TEMPDIR_PREFIX="nixpkcs."
_TEMPNAME_FORMAT="${_TEMPDIR_PREFIX}XXXXXXXX"
# shellcheck disable=SC2317
_tempdir_cleanup() {
  if [ -n "$_TEMPDIR" ] && [ -d "$_TEMPDIR" ] && [[ "$(basename -- "$_TEMPDIR")" == "$_TEMPDIR_PREFIX"* ]]; then
    rm -rf "$_TEMPDIR"
    _TEMPDIR=''
  fi
}

# Creates an empty file with extension $1 (default none) in the temp directory.
# Sets _TEMP to the path of the file, which will be 0 bytes and only writeable
# by the current user.
_TEMP=''
make_tempfile() {
  # Create the tempdir
  if [ -z "$_TEMPDIR" ] || [ ! -d "$_TEMPDIR" ]; then
    _TEMPDIR="$(mktemp -dt "$_TEMPNAME_FORMAT")"
    chmod 0700 "$_TEMPDIR"
    trap _tempdir_cleanup EXIT
  fi

  local filename="$_TEMPNAME_FORMAT"
  if [ $# -ge 1 ]; then
    # Add an extension.
    filename="$filename.$1"
  fi

  # Make sure the filename exists, only we can write to it, and it's empty, in that order
  filename="$(mktemp -p "$_TEMPDIR" -t "$filename")"
  touch "$filename"
  chmod 0600 "$filename"
  truncate -s0 "$filename"
  _TEMP="$filename"
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

# Acquire a lock if we need to.
if [[ -v NIXPKCS_LOCK_FILE ]] && [ -n "$NIXPKCS_LOCK_FILE" ] && command -v flock &>/dev/null; then
  lockfile="$NIXPKCS_LOCK_FILE"
  unset NIXPKCS_LOCK_FILE
  debug "Acquiring lock on $lockfile"
  exec flock -F "$lockfile" "$script_path" "$@"
  exit 255
fi

use_label=1
if [[ -v NIXPKCS_NO_LABELS ]] && [ -n "$NIXPKCS_NO_LABELS" ] && [ "$NIXPKCS_NO_LABELS" != '0' ]; then
  debug "Skipping labels because we were asked to."
  use_label=0
fi

# Deletes every non-alphanumeric, _, or -.
_SECRET=''
_SECRET_CHARS='0-9A-Za-z_-'
sanitize_secret() {
  local secret="$1"
  _SECRET="${secret//[^$_SECRET_CHARS]/}"
}

# Validates that the secret in $1 contains only alphanumerics, _, or -.
# Sets '_SECRET' if it's valid, or sets it to '' if not.
validate_secret() {
  local secret="$1"
  if [[ "$secret" =~ ^[$_SECRET_CHARS]+$ ]]; then
    sanitize_secret "$secret"
  else
    _SECRET=''
  fi
}

# Reads the file at $1 containing a secret.
# Sets '_SECRET' if it's valid and contains a secret, or '' and returns 1 if not.
read_secret_file() {
  local secret_file="$1"
  if [ -n "$secret_file" ]; then
    if [ -f "$secret_file" ]; then
      validate_secret "$(<"$secret_file")"
      if [ -n "$_SECRET" ]; then
        return 0
      else
        _SECRET=''
        error "Secret file '$secret_file' didn't appear to contain a valid secret"
        return 1
      fi
    else
      _SECRET=''
      error "Secret file '$secret_file' was specified and didn't exist"
      return 1
    fi
  else
    _SECRET=''
    return 0
  fi
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

  if [ "${#args[@]}" -lt 1 ]; then
    error "No arguments provided!"
    return 1
  fi

  # Clean up argv[0] for logging.
  log_args[0]="$(basename -- "${log_args[0]}")"

  info "<exec> $(printf '%q ' "${log_args[@]+"${log_args[@]}"}")"
  exec ${args[@]+"${args[@]}"}
)

# Runs pkcs11-tool.
# $1: The operation mode (anonymous|user|so).
# $@: The remaining pkcs11-tool args.
p11tool() {
  local op_mode="$1"
  shift

  # Remove leading zeroes from the ID.
  local id_str
  id_str="$(printf '%016x' "$id")"
  if [[ "$id_str" =~ ^(00)+([0-9a-f]{2,})$ ]]; then
    id_str="${BASH_REMATCH[2]}"
  fi

  local args=(--token-label "$token" --id "$id_str")

  if [ $use_label -ne 0 ]; then
    args+=(--label "$label")
  fi

  local secrets=()
  case "$op_mode" in
    anonymous)
      ;;
    user)
      if [ -n "$cert_options_user_pin" ]; then
        args+=(--login --login-type user --pin "$cert_options_user_pin")
        secrets+=("$cert_options_user_pin")
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
  log_exec "$cert_options_user_pin" "$key_options_so_pin" -- openssl "$@"
}

# Reads a certificate from the yubikey.
_CERT=''
read_cert() {
  info "Reading certificate"
  local cert
  set +e
  cert="$(p11tool user --read-object --type cert | openssl x509 -inform der)"
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

  # As of OpenSC 0.26.0, we can't use /dev/stdin here and need to write the cert to a tempfile.
  make_tempfile der
  echo "$certificate" | openssl x509 -inform pem -outform der >> "$_TEMP"
  p11tool so --write-object "$_TEMP" --type cert
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

# Calls a store init hook. Checks that we are unable to write to it first.
# $1: The name of the variable to use for the call.
# $2: --source to source it, --exec to exec it.
call_store_init_hook() (
  if [ $# -ne 2 ]; then
    error "Usage: [--source|--exec] VARIABLE_NAME"
    return 1
  fi

  local source=0
  case "$1" in
    --source)
      source=1
      ;;
    --exec)
      source=0
      ;;
    *)
      error "--source or --exec must be provided"
      return 1
      ;;
  esac

  local name="$2"
  if [[ -v "$name" ]] && [ -f "${!name}" ] && [ -x "${!name}" ]; then
    if [ -w "${!name}" ] || touch "${!name}" &>/dev/null; then
      error "$name (${!name}) was executable and writeable, aborting!"
      return 1
    else
      mkdir -p "$NIXPKCS_STORE_DIR"

      if [ $source -eq 0 ]; then
        exec "${!name}"
      else
        # shellcheck disable=SC1090
        . "${!name}"
      fi

      return 0
    fi
  fi
)

# Initializes the store if we need to.
maybe_init_store() {
  if [[ -v NIXPKCS_STORE_DIR ]] && [ -n "$NIXPKCS_STORE_DIR" ]; then
    info "Using store directory: $NIXPKCS_STORE_DIR"
    if [ ! -d "$NIXPKCS_STORE_DIR" ]; then
      # Get rid of the trailing newline on the PIN files, and make sure we own them.
      # The permissions should be fairly restrictive by default.
      local owner
      owner="$(id -u):$(id -g)"
      if [ -n "$key_options_so_pin" ] \
         && [ -n "$key_options_so_pin_file" ] && [ -f "$key_options_so_pin_file" ]; then
        info "Using SO PIN file: $key_options_so_pin_file"
        log_exec -- truncate -s0 "$key_options_so_pin_file"
        log_exec -- chown "$owner" "$key_options_so_pin_file"
        log_exec -- chmod 0600 "$key_options_so_pin_file"
        echo -n "$key_options_so_pin" >> "$key_options_so_pin_file" || true
      fi

      if [ -n "$cert_options_user_pin" ] \
         && [ -n "$cert_options_user_pin_file" ] \
         && [ -f "$cert_options_user_pin_file" ] \
         && [ "$(readlink -- "$cert_options_user_pin_file")" != "$(readlink -- "$key_options_so_pin_file")" ]; then
        info "Using User PIN file: $cert_options_user_pin_file"
        log_exec -- truncate -s0 "$cert_options_user_pin_file"
        log_exec -- chown "$owner" "$cert_options_user_pin_file"
        log_exec -- chmod 0600 "$cert_options_user_pin_file"
        echo -n "$cert_options_user_pin" >> "$cert_options_user_pin_file" || true
      fi

      info "Initializing store."

      # Run the one defined in the module.
      call_store_init_hook --source NIXPKCS_STORE_INIT

      # And any defined by the user.
      call_store_init_hook --exec NIXPKCS_STORE_INIT_HOOK

      info "Store initialized successfully."
    fi
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
  cert_options_validity_days cert_options_renewal_period cert_options_user_pin_file cert_options_rekey_hook

vars=(token id uri
  key_options_algorithm key_options_type key_options_so_pin_file key_options_force key_options_login_as_user
  cert_options_digest cert_options_serial cert_options_subject
  cert_options_validity_days cert_options_renewal_period cert_options_user_pin_file cert_options_rekey_hook
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
  if ! { openssl list -1 --digest-commands | grep -q "^${cert_options_digest}$"; }; then
    error "Invalid digest: $cert_options_digest. Use 'openssl list --digest-commands' for a list."
    exit 1
  fi
 
  # Read the pin file(s).
  read_secret_file "$key_options_so_pin_file"
  key_options_so_pin="$_SECRET"
  read_secret_file "$cert_options_user_pin_file"
  cert_options_user_pin="$_SECRET"
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

# Initialize the store.
maybe_init_store

# Read the certificate and run the rekey hook with the old cert.
if [ "$key_options_force" != 'true' ]; then
  read_cert
  if [ -n "$_CERT" ]; then
    echo "$_CERT" | run_rekey_hook "$label" old

    if [ $_REKEY_STATUS -ne 0 ]; then
      warn "Rekey hook returned $_REKEY_STATUS; skipping rekey."
    fi
  fi
fi

# Check if we need to regenerate the key.
if [ $_REKEY_STATUS -eq 0 ] && { [ -z "$_CERT" ] || is_expiring "$_CERT" "$cert_options_renewal_period"; }; then
  gen_key
  read_cert
  if is_expiring "$_CERT" "$cert_options_renewal_period"; then
    warn "Generated a cert that's about to expire!"
  fi

  echo "$_CERT" | run_rekey_hook "$label" new

  if [ $_REKEY_STATUS -ne 0 ]; then
    warn "Rekey hook returned $_REKEY_STATUS."
  fi
fi

echo "$_CERT"
exit 0

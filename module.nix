self:

{ config, pkgs, lib, ... }:

with lib;

let
  # Creates a PKCS#11 URI.
  mkPkcs11Uri = {
    authority, # The authority
    query ? {} # The query
  }: let
    /* Converts an integer to a value in a PKCS#11 URI using the following rules:
     * 0:   %00
     * 1:   %01
     * 10:  %0a
     * 256: %01%00
     * ...
     * That is: it's interpreted as a 63-bit positive integer and leading zeroes are stripped.
     */
    intToUriValue = value:
      let
        zero = "%00";

        # Support Nix's full integer width for PKCS#11 IDs.
        paddedValue = fixedWidthString 16 "0" (toHexString value);
        splitValue = builtins.split "([0-9A-F]{2})" paddedValue;
        replacedValue = lib.imap0
          (
            idx: vals:
            let
              even = lib.mod idx 2 == 0;
              val = if even then vals else builtins.elemAt vals 0;
              length = builtins.length splitValue;
            in
            if even && idx < length - 1 && val == "" then "%" else val
          ) splitValue;
        deprefixedValue = let
          split = builtins.split "^(${lib.escapeRegex zero})+" (lib.concatStrings replacedValue);
        in builtins.elemAt split (builtins.length split - 1);
      in
      if deprefixedValue == "" then zero else deprefixedValue;

    # Serializes a string or int to a PKCS#11 value.
    serializePkcs11UriValue = value:
      if builtins.isInt value && value >= 0 then
        intToUriValue value
      else if builtins.isString value then
        escapeURL value
      else
        throw "only 8-bit ints and strings are supported in PKCS#11 URIs; got '${builtins.type value}'";
    
    # Converts a list of URI attrs to a query string.
    toQuery = mapAttrsToList (name: value: 
      if value == null then null else (escapeURL name) + "=" + (serializePkcs11UriValue value)
    );

    # The authority string. Just a query string joined with ;.
    authorityString = concatStringsSep ";" (builtins.filter (x: x != null) (toQuery authority));

    # The query string.
    queryString =
      let
        queryValue = concatStringsSep "&" (builtins.filter (x: x != null) (toQuery query));
      in
      if queryValue == "" then "" else "?" + queryValue;
  in
  "pkcs11:" + authorityString + queryString;

  # The nixpkcs config.
  cfg = config.nixpkcs;
in
{
  options = {
    nixpkcs = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Set to true to enable automated key management using nixpkcs.";
      };

      pcsc = {
        enable = mkOption {
          type = types.bool;
          default = false;
          description = "Set to true to enable PKCS#11 support using pcsc-lite";
        };
        users = mkOption {
          description = "Any users that should be allowed to access pcsc-lite.";
          default = [];
          example = ["alice"];
          type = types.listOf types.str;
        };
      };

      tpm2 = {
        enable = mkOption {
          type = types.bool;
          default = false;
          description = "Set to true to enable TPM2 support";
        };
      };

      environment = {
        enable = mkOption {
          type = types.bool;
          default = true;
          description = "Set to true to populate the system environment with nixpkcs keypairs' extraEnv.";
        };
      };

      uri = {
        enable = mkOption {
          type = types.bool;
          default = true;
          description = "Set to true to enable the `nixpkcs-uri` command converting keypair names into URIs.";
        };

        package = mkOption {
          type = types.package;
          default = pkgs.writeShellApplication {
            name = "nixpkcs-uri";
            text = ''
              set -euo pipefail
              if [ $# -ne 1 ]; then
                echo "Usage: $0 <key name>" >&2
                exit 1
              fi

              case "$1" in
                ${lib.concatStringsSep "\n  " (lib.mapAttrsToList (name: value: "${lib.escapeShellArg name}) echo ${lib.escapeShellArg value.uri} ;;") cfg.keypairs)}
                *) echo "unknown key '$1'" >&2 && exit 1 ;;
              esac
            '';
          };
          description = "Override the nixpkcs-uri package, used to convert key names into PKCS#11 URIs.";
        };
      };

      keypairs = mkOption {
        description = "Keypairs to let nixpkcs manage on this host.";
        default = {};
        type = types.attrsOf (types.submodule ({ name, config, ... }: {
          options = let
            authority = {
              inherit (config) token id;
              slot-id = if config.slot == null then null else toString config.slot;
              type = "private";
            } // lib.optionalAttrs (!(config.pkcs11Module.noLabels or false)) {
              # Only supply this for tokens that support labels.
              object = name;
            };
            query = lib.optionalAttrs (config.certOptions.pinFile != null) {
              pin-source = "file:${config.certOptions.pinFile}";
            };
          in {
            enable = mkOption {
              type = types.bool;
              default = true;
              description = "Set to true to disable this key.";
            };

            pkcs11Module = mkOption {
              type = types.attrs;
              description = "The PKCS#11 module to use for this key.";
              example = lib.literalExpression ''
                inherit (pkgs.yubico-piv-tool) pkcs11Module;
              '';
            };

            storeInitHook = mkOption {
              type = types.nullOr types.path;
              default = pkgs.writeShellScript "default-store-init-hook" ":";
              description = ''
                Run the given script after the store is initialized and before nixpkcs runs.

                This script has NIXPKCS_STORE_DIR exported to it.

                This script also always has access to a wrapped OpenSSL and pkcs11-tool on its PATH, in addition to jq.
                Returning nonzero from this script aborts nixpkcs.
              '';
              example = lib.literalExpression ''
                pkgs.writeShellScript "store-init-hook" '''
                  chown -R alice:users "$NIXPKCS_STORE_DIR"
                '''
              '';
            };

            token = mkOption {
              type = types.str;
              default = "nixpkcs";
              description = "The token label.";
              example = "YubiKey PIV #123456";
            };

            id = mkOption {
              type = types.ints.unsigned;
              description = "The PKCS#11 key ID.";
              example = 42;
            };

            slot = mkOption {
              type = types.nullOr types.ints.u8;
              default = null;
              description = "The PKCS#11 slot ID. Not always required, but may be in some cases.";
              example = 42;
            };

            uri = mkOption {
              type = types.str;
              default = mkPkcs11Uri {
                inherit authority;
                query = query // {
                  module-path = config.pkcs11Module.path;
                };
              };
              description = "Overrides the PKCS#11 URI.";
              example = "pkcs11:token=YubiKey%20PIV%20%23123456;id=%05;type=private";
            };

            rfc7512Uri = mkOption {
              type = types.str;
              default = mkPkcs11Uri {
                inherit authority query;
              };
              description = "Overrides the PKCS#11 URI for applications that strictly follow the RFC.";
              example = "pkcs11:token=YubiKey%20PIV%20%23123456;id=%05;type=private";
            };

            extraEnv = mkOption {
              type = types.attrsOf types.str;
              default = config.pkcs11Module.mkEnv {};
              description = "Extra environment variables to pass to this key's systemd unit";
              example = lib.literalExpression ''
                { NSS_LIB_PARAMS = "configDir=/etc/softokn"; }
              '';
            };

            debug = mkOption {
              type = types.bool;
              default = false;
              description = "Set to true to output verbose debugging messages for this key.";
              example = true;
            };

            keyOptions = {
              algorithm = mkOption {
                type = types.str;
                default = "EC";
                description = "The key algorithm (EC, RSA).";
                example = "EC";
              };

              type = mkOption {
                type = types.str;
                default = "secp384r1";
                description = "The type of key to generate. Algorithm specific.";
                example = "secp256r1";
              };

              usage = mkOption {
                type = types.listOf types.str;
                default = [ "sign" "derive" ];
                description = "The key usage. An array of sign|derive|decrypt|wrap.";
                example = lib.literalExpression ''
                  ["sign" "derive" "decrypt"]
                '';
              };

              soPinFile = mkOption {
                type = types.nullOr types.path;
                default = null;
                description = "The file containing the security officer PIN.";
                example = "/etc/nixpkcs/so.pin";
              };

              force = mkOption {
                type = types.bool;
                default = false;
                description = "Regenerate the key every time. This is dangerous, and is disabled by default.";
                example = true;
              };

              loginAsUser = mkOption {
                type = types.bool;
                default = true;
                description = "Some tokens use the user login for key generation, and the SO login for personalization. If set, this will log in as the 'user' instead.";
                example = true;
              };
            };

            certOptions = {
              digest = mkOption {
                type = types.str;
                default = "SHA256";
                description = "The digest to use for this certificate.";
                example = "SHA384";
              };

              serial = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = "The serial to use for this certificate. Set to null to autogenerate. This should be a hex string, not decimal.";
                example = "09f91102";
              };

              validityDays = mkOption {
                type = types.ints.positive;
                default = 365;
                description = "The number of days that this cert should be valid for.";
                example = 365 * 3;
              };

              renewalPeriod = mkOption {
                type = types.ints.positive;
                default = 14;
                description = "The number of days before expiration that this certificate should be renewed. Set to -1 to disable auto-renewal.";
                example = 14;
              };

              subject = mkOption {
                type = types.str;
                default = "O=NixOS/CN=nixpkcs Certificate";
                description = "The subject to use for this certificate.";
                example = "C=US/ST=California/L=Carlsbad/O=nixpkcs/CN=nixpkcs Example CA";
              };

              extensions = mkOption {
                type = types.listOf types.str;
                default = [];
                description = ''
                  Extensions to add. See OpenSSL documentation for the syntax.
                  If a `key=value` formatted item is provided, will add it using `-addext`.
                  Otherwise, adds it using `-extensions`.
                '';
                example = lib.literalExpression ''
                  ["v3_ca" "keyUsage=critical,nonRepudiation,keyCertSign,digitalSignature,cRLSign"]
                '';
              };

              pinFile = mkOption {
                type = types.nullOr types.path;
                default = null;
                description = "The file containing the user PIN.";
                example = "/etc/nixpkcs/user.pin";
              };

              writeTo = mkOption {
                type = types.nullOr types.path;
                default = null;
                description = "Write the certificate to this path whenever we regenerate it. Overridden by manually setting rekeyHook.";
                example = "/home/alice/cert.crt";
              };

              rekeyHook = mkOption {
                type = types.nullOr types.path;
                default = if config.certOptions.writeTo == null
                          then null
                          else pkgs.writeShellScript "default-rekey-hook" ''
                            cat > ${escapeShellArg config.certOptions.writeTo}
                          '';
                description = ''
                  Run the given script whenever nixpkcs runs. The certificate is passed in on stdin.
                  NIXPKCS_KEY_SPEC is passed in as an environment variable, containing the NixOS module options.
                  You may use this to restart services when keys change.

                  - $1 is set to the name of the key.
                  - $2 is set to 'old' or 'new' depending on whether the certificate is the old or new one.
                  You may use this to do something with the certificate when it's checked or when it's renewed.

                  This script always has access to a wrapped OpenSSL and pkcs11-tool on its PATH, in addition to jq.
                  Returning nonzero from this script aborts rekey but returns normally.
                '';
                example = lib.literalExpression ''
                  pkgs.writeShellScript "rekey-hook" '''
                    if [ "$2" == 'new' ]; then
                      cat > /home/alice/cert.crt
                      chown alice:alice /home/alice/cert.crt
                    fi
                  '''
                '';
              };
            };
          };
        }));
      };
    };
  };

  config = let
    enabledKeypairs = if cfg.enable then lib.filterAttrs (_: value: value.enable) cfg.keypairs else [];
  in mkMerge [
    (mkIf cfg.enable {
      environment = {
        # Place the nixpkgs-uri package on PATH.
        systemPackages = mkIf cfg.uri.enable (lib.singleton cfg.uri.package);

        # Automatically set environment variables for the specified keypairs.
        variables = mkIf cfg.environment.enable
          (lib.foldl (s: x: s // x) {} (lib.mapAttrsToList (name: value: value.extraEnv) enabledKeypairs));
      };

      systemd.services = lib.mapAttrs' (name: value:
        lib.nameValuePair "nixpkcs@${name}" {
          description = "nixpkcs service for key '${name}'";
          startAt = "*-*-* 00:00:00";
          wants = [ "basic.target" ];
          after = [ "basic.target" "multi-user.target" ];
          wantedBy = [ "multi-user.target" ];
          environment = let
            # Escapes systemd %-specifiers in the given value.
            escapeSpecifiers = value: builtins.replaceStrings ["%"] ["%%"] (builtins.toString value);
          in lib.mapAttrs (_: envValue: (escapeSpecifiers envValue)) (value.extraEnv // {
            NIXPKCS_KEY_SPEC = let
              filteredValue = {
                # We don't want to pass the whole PKCS#11 module here; this should be enough.
                inherit (value) token id uri keyOptions certOptions;
              };
            in builtins.toJSON filteredValue;
            NIXPKCS_LOCK_FILE = let
              # Come up with a lockfile key. We want to avoid concurrently running two instances
              # of the script that use the same PKCS#11 module since there will frequently be
              # connections to hardware involved. Better safe than sorry with hardware and
              # cryptographic keying, and this involves both. So just use the Nix store path
              # of the PKCS#11 token library we are using.
              pkcs11ModuleKey = builtins.substring 0 8
                (builtins.hashString "sha256" value.pkcs11Module.path);
              lockfileKey = "nixpkcs-${pkcs11ModuleKey}.lock";
            in "/var/lock/${lockfileKey}";
          } // lib.optionalAttrs ((value.pkcs11Module.storeInit or null) != null) {
            NIXPKCS_STORE_INIT = value.pkcs11Module.storeInit;
          } // lib.optionalAttrs (value.storeInitHook != null) {
            NIXPKCS_STORE_INIT_HOOK = value.storeInitHook;
          } // lib.optionalAttrs (value.pkcs11Module.noLabels or false) {
            # For, e.g. Yubikeys, which don't support them.
            NIXPKCS_NO_LABELS = 1;
          } // lib.optionalAttrs value.debug {
            NIXPKCS_DEBUG = 1;
          });
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "@${pkgs.nixpkcs.withPkcs11Module value}/bin/nixpkcs.sh nixpkcs ${name}";
          };
        }
      ) enabledKeypairs;
    })
    (mkIf cfg.pcsc.enable {
      services.pcscd.enable = true;
    })
    (mkIf (cfg.pcsc.enable && builtins.length cfg.pcsc.users > 0) {
      environment.systemPackages = let
        pcscPolkitRule = pkgs.writeTextDir "share/polkit-1/rules.d/10-pcsc.rules" ''
          var users = ${builtins.toJSON cfg.pcsc.users};
          polkit.addRule(function (action, subject) {
            if (action.id === "org.debian.pcsc-lite.access_pcsc" ||
                action.id === "org.debian.pcsc-lite.access_card") {
              for (var idx = 0; idx < users.length; idx++) {
                if (subject.user === users[idx]) {
                  return polkit.Result.YES;
                }
              }
              return polkit.Result.NO;
            }
          });
        '';
      in lib.singleton pcscPolkitRule;
    })
    (mkIf cfg.tpm2.enable {
      security.tpm2 = {
        enable = true;
        abrmd.enable = true;
      };
    })
  ];
}

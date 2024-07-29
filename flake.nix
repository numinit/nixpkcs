{
  description = "Add support for PKCS#11 smartcards to various Nix packages";
  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
  };

  outputs = inputs@{ self, flake-parts, nixpkgs, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        inputs.flake-parts.flakeModules.easyOverlay
      ];

      flake = {
        nixosModules.default = import ./module.nix self;
        version = "1.1.5";
      };

      systems = [ "x86_64-linux" "aarch64-linux" ];

      perSystem = { config, system, pkgs, final, lib, ... }: {
        _module.args.pkgs = import inputs.nixpkgs {
          inherit system;
          overlays = [
            self.overlays.default
          ];
          config = { };
        };

        checks = {
          nssNebulaTest = pkgs.callPackage ./nixos/tests/nebula.nix {
            inherit self nixpkgs;
            inherit (pkgs.nss_latest) pkcs11Module;
            extraKeypairOptions = {
              token = "NSS Certificate DB";
              slot = 2;
              storeInitHook = pkgs.writeShellScript "nss-test-store-init" ''
                chown -R nebula-nixpkcs:nebula-nixpkcs "$NIXPKCS_STORE_DIR" || true

                key_options_so_pin_file="$(echo "$NIXPKCS_KEY_SPEC" | jq -r '.keyOptions?.soPinFile? // ""')"
                if [ -n "$key_options_so_pin_file" ] && [ -f "$key_options_so_pin_file" ]; then
                  chown nebula-nixpkcs:nebula-nixpkcs "$key_options_so_pin_file" || true
                fi
                cert_options_user_pin_file="$(echo "$NIXPKCS_KEY_SPEC" | jq -r '.certOptions?.pinFile? // ""')"
                if [ -n "$cert_options_user_pin_file" ] && [ -f "$cert_options_user_pin_file" ]; then
                  chown nebula-nixpkcs:nebula-nixpkcs "$cert_options_user_pin_file" || true
                fi
              '';
            };
          };
          tpmNebulaTest = pkgs.callPackage ./nixos/tests/nebula.nix {
            inherit self nixpkgs;
            inherit (pkgs.tpm2-pkcs11) pkcs11Module;
            baseKeyId = 256; # swtpm supports rather high IDs, we should test them...
            extraKeypairOptions = {
              token = "nixpkcs";
            };
            extraMachineOptions = { config, ... }: {
              virtualisation.tpm.enable = true;
              nixpkcs.tpm2.enable = true;
              users.users."nebula-nixpkcs" = lib.mkIf (config.services.nebula.networks.nixpkcs.enable or false) {
                extraGroups = [ "tss" ];
              };
            };
          };
          nginxTest = pkgs.callPackage ./nixos/tests/nginx.nix {
            inherit self nixpkgs;
            inherit (pkgs.tpm2-pkcs11) pkcs11Module;
            extraKeypairOptions = {
              token = "nixpkcs";
            };
            extraMachineOptions = { config, ... }: {
              virtualisation.tpm.enable = true;
              nixpkcs.tpm2.enable = true;
              users.users.nginx = {
                extraGroups = [ "tss" ];
              };
            };
          };
        };

        packages = {
          inherit (pkgs) nebula openssl opensc pkcs11-provider nss_latest yubico-piv-tool tpm2-pkcs11;
        };

        overlayAttrs = with pkgs; let
          # Creates an attrset mapping package names to that package with the given PKCS#11 module.
          mkPkcs11Consumers = package:
            let
              pkcs11Consumers = [
                "nixpkcs"
                "opensc"
                "openssl"
              ];
            in
            builtins.listToAttrs (
              map (name: lib.nameValuePair name (final.${name}.withPkcs11Module package)) pkcs11Consumers
            );

          # Wraps a package with a symlink join that respects overrides.
          symlinkJoinWith =
            { package
            , pkcs11Module
            , moduleEnv ? { }
            , passthru ? { }
            , extraWrapProgramArgs ? [ ]
            , findDirectory ? "bin"
            , extraFindArgs ? [ ]
            }@args: symlinkJoin {
              name = "${package.pname}-with-pkcs11";
              paths = [ package ];
              buildInputs = [ makeWrapper ];
              postBuild = ''
                args=(${lib.escapeShellArgs (lib.flatten (lib.mapAttrsToList (name: value: ["--set-default" name value]) (pkcs11Module.mkEnv moduleEnv)))})
                args+=(${lib.escapeShellArgs extraWrapProgramArgs})
                find -L $out/${lib.escapeShellArg findDirectory} -type f ${lib.escapeShellArgs extraFindArgs} | while read program; do
                  wrapProgram "$program" "''${args[@]}"
                done
              '';
              passthru = {
                # If the resulting package is overridden, use the symlinkJoinWith wrapper.
                # (nginx needs this, as an example)
                inherit (package) pname version;
                override = attrs: symlinkJoinWith (args // {
                  package = package.override attrs;
                });
              } // passthru;
            };
        in
        {
          ### PATCHES ###

          nebula =
            let
              src = fetchFromGitHub {
                owner = "numinit";
                repo = nebula.pname;
                rev = "refs/tags/pkcs11-v${nebula.version}";
                hash = "sha256-TKAa6gkga8n7DkM0Gl+EW2OjJt+csTd6O5eVGhN9YOk=";
              };
              version = "${nebula.version}-pkcs11";
            in
            (nebula.override {
              buildGoModule = args: buildGoModule (args // {
                inherit src version;
                vendorHash = "sha256-qv3/7CHcCEDRM3lI+/XIsG/plF+0N5JU5y1kGYfXeGo=";
              });
            }).overrideAttrs (package: {
              inherit src version;
              tags = [ "pkcs11" ] ++ (package.tags or [ ]);
            });

          ### WRAPPERS ###

          nixpkcs = {
            name = "nixpkcs";
            withPkcs11Module = { pkcs11Module, ... }: writeShellApplication {
              name = "nixpkcs.sh";
              runtimeInputs = [
                util-linux
                jq
                (final.opensc.withPkcs11Module { inherit pkcs11Module; })
                (final.openssl.withPkcs11Module { inherit pkcs11Module; })
              ];
              text = builtins.readFile ./nixpkcs.sh;
            };
          };

          openssl = openssl.overrideAttrs (finalPackage: previousPackage: with final; {
            passthru = (previousPackage.passthru or { }) // {
              /**
               * Creates a symlinkJoin wrapper to run any program with a PKCS#11 module loaded into OpenSSL.
               */
              withPkcs11Module =
                {
                  # contains two keys: `path` and `options`
                  pkcs11Module
                , # the package whose bin directory to wrap
                  package ? openssl.bin
                , # the root config option, may need changing (e.g. to "nodejs_conf" for nodejs)
                  confName ? "openssl_conf"
                , # the name for the legacy engine, if enabled
                  engineName ? "pkcs11"
                , # true if we should load p11-kit as a legacy engine
                  enableLegacyEngine ? false
                , # extra options for the engine
                  extraEngineOptions ? { }
                , # the name for the new-style provider, if enabled
                  providerName ? "pkcs11"
                , # true to enable the provider
                  enableProvider ? true
                , # extra options to pass to the provider.
                  extraProviderOptions ? { }
                , # environment variables to set
                  moduleEnv ? { }
                , # passthru on the symlinkJoin
                  passthru ? { }
                , # true to enable debugging
                  debug ? false
                , ...
                }:
                let
                  # Adds an ordering prefix to a string.
                  addOrder = order: str: "${builtins.toString order}-${str}";

                  # Adds an ordering prefix to all keys in an attrset.
                  addOrderToAttrs = order: lib.attrsets.mapAttrs' (name: value: lib.nameValuePair (addOrder order name) value);

                  # Strips an ordering prefix from a string.
                  stripOrder = str:
                    let
                      match = builtins.match "([[:digit:]]+-)?(.*)" str;
                    in
                    if match != null && builtins.length match > 0 then
                      builtins.elemAt match ((builtins.length match) - 1)
                    else
                      str;

                  # The PKCS#11 module options.
                  moduleOptions = if pkcs11Module == null then { } else pkcs11Module.openSslOptions or { };

                  # The PKCS#11 engine options.
                  engineOptions = {
                    default_algorithms = "ALL";
                  } // extraEngineOptions;

                  # The provider options. Defaults to loading provider URLs from PEM files.
                  providerOptions = {
                    pkcs11-module-encode-provider-uri-to-pem = true;
                    pkcs11-module-load-behavior = "early";
                  } // lib.optionalAttrs (pkcs11Module != null) {
                    pkcs11-module-path = "${pkcs11Module.path}";
                  } // moduleOptions // extraProviderOptions;

                  # The OpenSSL config.
                  config =
                    let
                      cnfPrefix = "${package.pname}-with-pkcs11";
                      originalMkKeyValue = lib.generators.mkKeyValueDefault { } " = ";
                      mkKeyValue = k: v:
                        let
                          stripped = stripOrder k;
                          normalizedValue = if v == null then "EMPTY" else v;
                        in
                        if stripped == ".include" then
                          ".include ${v}"
                        else
                          originalMkKeyValue stripped normalizedValue;
                    in
                    writeText "${cnfPrefix}.openssl.cnf" (lib.generators.toINIWithGlobalSection
                      {
                        inherit mkKeyValue;
                        listsAsDuplicateKeys = true;
                      }
                      {
                        globalSection = {
                          ${addOrder 10 confName} = "openssl_init";
                          ${addOrder 11 ".include"} = "${openssl.out}/etc/ssl/openssl.cnf";
                        };

                        sections = {
                          openssl_init = { }
                            // (lib.optionalAttrs enableLegacyEngine (addOrderToAttrs 10 { engines = "engine_section"; }))
                            // (lib.optionalAttrs enableProvider (addOrderToAttrs 11 { providers = "provider_section"; }));
                        } // (lib.optionalAttrs enableLegacyEngine {
                          engine_section = {
                            ${engineName} = "${engineName}_engine_section";
                          };
                          "${engineName}_engine_section" = {
                            ${addOrder 10 "engine_id"} = engineName;
                            ${addOrder 11 "dynamic_path"} = "${libp11}/lib/engines/libpkcs11.so";
                            ${addOrder 99 "init"} = 1;
                          } // lib.optionalAttrs (debug != null && debug != false) {
                            ${addOrder 12 "VERBOSE"} = null;
                          } // lib.optionalAttrs (pkcs11Module != null) {
                            ${addOrder 13 "MODULE_PATH"} = pkcs11Module.path;
                          } // (addOrderToAttrs 20 engineOptions);
                        }) // {
                          provider_section = {
                            ${addOrder 10 "default"} = "default_provider_section";
                          } // (lib.optionalAttrs enableProvider {
                            ${addOrder 11 providerName} = "${providerName}_provider_section";
                          });
                          default_provider_section = (addOrderToAttrs 99 { activate = 1; });
                        } // (lib.optionalAttrs enableProvider {
                          "${providerName}_provider_section" = {
                            ${addOrder 10 "module"} = "${pkcs11-provider}/lib/ossl-modules/pkcs11.so";
                            ${addOrder 99 "activate"} = 1;
                          } // (addOrderToAttrs 20 providerOptions);
                        });
                      });
                  providerDebugLevel = let realDebug = if debug == true then 2 else debug; in
                    if builtins.isString realDebug then realDebug
                    else if builtins.isInt realDebug then "file:/dev/stderr,level:${builtins.toString realDebug}"
                    else null;
                in
                symlinkJoinWith {
                  inherit package pkcs11Module moduleEnv passthru;
                  extraWrapProgramArgs =
                    [ "--set" "OPENSSL_CONF" config ]
                      ++ lib.optionals enableProvider [ "--set" "PKCS11_PROVIDER_MODULE" pkcs11Module.path ]
                      ++ lib.optionals (enableProvider && providerDebugLevel != null) [ "--set-default" "PKCS11_PROVIDER_DEBUG" providerDebugLevel ];
                };
            };
          });

          opensc = opensc.overrideAttrs (finalPackage: previousPackage: {
            passthru = (previousPackage.passthru or { }) // {
              withPkcs11Module =
                {
                  # the module
                  pkcs11Module
                , # environment variables to set; see <module>.mkEnv
                  moduleEnv ? { }
                , # passthrus to add to the symlinkJoin
                  passthru ? { }
                , ...
                }: symlinkJoinWith {
                  package = finalPackage.finalPackage;
                  inherit pkcs11Module moduleEnv passthru;
                  extraWrapProgramArgs = [ "--add-flags" "--module ${pkcs11Module.path}" ];
                  extraFindArgs = [ "-name" "pkcs11-tool" ];
                };
            };
          });

          pkcs11-provider = pkcs11-provider.overrideAttrs (finalPackage: previousPackage: with final; {
            passthru = (previousPackage.passthru or { }) // {
              uri2pem = stdenv.mkDerivation {
                pname = "pkcs11-provider-uri2pem";
                inherit (previousPackage) version src;

                buildInputs = [
                  (python3.withPackages (pkgs: lib.singleton pkgs.asn1crypto))
                ];

                dontBuild = true;

                installPhase = ''
                  mkdir -p $out/bin
                  echo '#!/usr/bin/env python3' > $out/bin/uri2pem
                  cat tools/uri2pem.py | grep -v '^#!' >> $out/bin/uri2pem
                  chmod +x $out/bin/uri2pem
                '';

                passthru.__functor = self: uri: pkgs.runCommand "pkcs11-uri2pem" { inherit uri; } ''
                  ${self}/bin/uri2pem --out "$out" "$uri"
                '';
              };
            };
          });

          ### MODULES ###

          # nss is broken for this usecase but nss_latest is not.
          # We're only maintaining one of these things.
          nss_latest = nss_latest.overrideAttrs (finalPackage: previousPackage: {
            passthru = (previousPackage.passthru or { }) // {
              pkcs11Module = {
                path = "${finalPackage.finalPackage}/lib/libsoftokn3.so";
                openSslOptions = { };
                mkEnv =
                  { storeDir ? "/etc/pki/nssdb"
                  , extraEnv ? { }
                  }: {
                    NSS_LIB_PARAMS = "configDir=${storeDir}";
                    NIXPKCS_STORE_DIR = storeDir;
                  } // extraEnv;
                storeInit = pkgs.writeShellScript "nss-pkcs11-init" ''
                  local pin="$cert_options_user_pin"
                  if [ -z "$pin" ]; then
                    pin="$key_options_so_pin"
                  fi
                  if [ -z "$pin" ]; then
                    error "User or Security Officer PIN must be set"
                    return 1
                  fi
                  echo -n "$pin" | log_exec -- ${finalPackage.finalPackage.tools}/bin/certutil -N \
                    -d "$NIXPKCS_STORE_DIR" -f /dev/stdin
                '';
              };
            } // (mkPkcs11Consumers finalPackage.finalPackage);
          });

          tpm2-pkcs11 = (tpm2-pkcs11.override {
            fapiSupport = false;
          }).overrideAttrs (finalPackage: previousPackage: {
            src = fetchFromGitHub {
              owner = "tpm2-software";
              repo = finalPackage.pname;
              # Needed to support key agreement with TPM2
              rev = "eb3897be3bd6d837b2d4819507c1f787624510e2";
              hash = "sha256-7ftit6g3FT5qwlJhgbYHBvXoDNJeyF9cIScEIgCPlcA=";
            };

            # Silence spammy warnings
            configureFlags = (previousPackage.configureFlags or [ ]) ++ [ "--with-fapi=no" ];

            passthru = (previousPackage.passthru or { }) // {
              pkcs11Module = {
                path = "${finalPackage.finalPackage}/lib/libtpm2_pkcs11.so";
                openSslOptions = {
                  pkcs11-module-quirks = "no-operation-state";
                };
                mkEnv =
                  { storeDir ? "/etc/tpm2-pkcs11"
                  , # error
                    logLevel ? 0
                  , disableFapiLogging ? true
                  , extraEnv ? { }
                  }: {
                    TPM2_PKCS11_STORE = storeDir;
                    TPM2_PKCS11_BACKEND = "esysdb";
                    TPM2_PKCS11_LOG_LEVEL = builtins.toString logLevel;
                    NIXPKCS_STORE_DIR = storeDir;
                  } // lib.optionalAttrs disableFapiLogging {
                    TSS2_LOG = "fapi+NONE";
                  } // extraEnv;
                storeInit = pkgs.writeShellScript "tpm2-pkcs11-init" ''
                  if [ -z "$key_options_so_pin" ] || [ -z "$cert_options_user_pin" ]; then
                    error "Security Officer and User PIN must be set to initialize the TPM"
                    return 1
                  fi

                  # Initialize the TPM.
                  log_exec -- \
                    ${finalPackage.finalPackage.bin}/bin/tpm2_ptool init --path="$NIXPKCS_STORE_DIR"
                  log_exec "$key_options_so_pin" "$cert_options_user_pin" -- \
                    ${finalPackage.finalPackage.bin}/bin/tpm2_ptool addtoken --pid=1 \
                      --sopin="$key_options_so_pin" \
                      --userpin="$cert_options_user_pin" \
                      --label="$token" --path="$NIXPKCS_STORE_DIR"

                  # Ensure permissions on the store directory.
                  owner="$(id -u)"
                  log_exec -- chown -R "$owner:tss" "$NIXPKCS_STORE_DIR"
                  log_exec -- chmod 0770 "$NIXPKCS_STORE_DIR"
                  log_exec -- find "$NIXPKCS_STORE_DIR" -type f -exec chmod 0660 {} \;

                  # Ensure permissions on the SO PIN and user PIN.
                  if [ -n "$key_options_so_pin_file" ] && [ -f "$key_options_so_pin_file" ]; then
                    log_exec -- chown "$owner:tss" "$key_options_so_pin_file"
                    log_exec -- chmod 0640 "$key_options_so_pin_file"
                  fi
                  if [ -n "$cert_options_user_pin_file" ] && [ -f "$cert_options_user_pin_file" ]; then
                    log_exec -- chown "$owner:tss" "$cert_options_user_pin_file"
                    log_exec -- chmod 0640 "$cert_options_user_pin_file"
                  fi
                '';

              };
            } // (mkPkcs11Consumers finalPackage.finalPackage);
          });

          yubico-piv-tool = yubico-piv-tool.overrideAttrs (finalPackage: previousPackage: {
            passthru = (previousPackage.passthru or { }) // {
              pkcs11Module = {
                path = "${finalPackage.finalPackage}/lib/libykcs11.so";
                openSslOptions = {
                  pkcs11-module-login-behavior = "never";
                  pkcs11-module-quirks = "no-deinit no-operation-state";
                  pkcs11-module-cache-pins = "cache";
                };
                noLabels = true;
                mkEnv =
                  { debug ? 0
                  , extraEnv ? { }
                  }: {
                    YKCS11_DBG = builtins.toString debug;
                  } // extraEnv;
              };
            } // (mkPkcs11Consumers finalPackage.finalPackage);
          });
        };
      };
    };
}

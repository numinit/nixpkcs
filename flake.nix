{
  description = "Add support for PKCS#11 smartcards to various Nix packages";
  inputs = {};

  outputs = { ... }: {
    overlays.default = final: prev: with prev; {
      nebula = let
        src = fetchFromGitHub {
          owner = "numinit";
          repo = nebula.pname;
          rev = "refs/tags/pkcs11-v${nebula.version}";
          hash = "sha256-X0+f/6T+49/vhlchvhmMBFSVaEZXlxET4aEngJGheGM=";
        };
        version = "${nebula.version}-pkcs11";
      in
      (nebula.override {
        buildGoModule = args: buildGoModule (args // {
          inherit src version;
          vendorHash = "sha256-qv3/7CHcCEDRM3lI+/XIsG/plF+0N5JU5y1kGYfXeGo=";
        });
      })
      .overrideAttrs (package: {
        inherit src version;
        tags = [ "pkcs11" ] ++ (package.tags or []);
      });

      openssl = openssl.overrideAttrs (package: with final; {
        passthru = (package.passthru or {}) // {
          /**
           * Creates a symlinkJoin wrapper to run any program with a PKCS#11 module loaded into OpenSSL.
           */
          withPkcs11Module = {
            pkcs11Module,               # contains two keys: `path` and `options`
            package ? openssl.bin,      # the package whose bin directory to wrap
            confName ? "openssl_conf",  # the root config option, may need changing (e.g. to "nodejs_conf" for nodejs)
            engineName ? "pkcs11",      # the name for the legacy engine, if enabled
            enableLegacyEngine ? false, # true if we should load p11-kit as a legacy engine
            extraEngineOptions ? {},    # extra options for the engine
            providerName ? "pkcs11",    # the name for the new-style provider, if enabled
            enableProvider ? true,      # true to enable the provider
            extraProviderOptions ? {},  # extra options to pass to the provider.
            ...
          }: let
            # Adds an ordering prefix to a string.
            addOrder = order: str: "${builtins.toString order}-${str}";

            # Adds an ordering prefix to all keys in an attrset.
            addOrderToAttrs = order: lib.attrsets.mapAttrs' (name: value: lib.nameValuePair (addOrder order name) value);

            # Strips an ordering prefix from a string.
            stripOrder = str: let
              match = builtins.match "([[:digit:]]+-)?(.*)" str;
            in
              if match != null && builtins.length match > 0 then
                builtins.elemAt match ((builtins.length match) - 1)
              else
                str;

            # The PKCS#11 module options.
            moduleOptions = pkcs11Module.options or {};

            # The PKCS#11 engine options.
            engineOptions = {
              default_algorithms = "ALL";
            } // extraEngineOptions;

            # The provider options. Defaults to loading provider URLs from PEM files.
            providerOptions = {
              pkcs11-module-path = "${pkcs11Module.path}";
              pkcs11-module-encode-provider-uri-to-pem = true;
              pkcs11-module-load-behavior = "early";
            } // moduleOptions // extraProviderOptions;

            # The OpenSSL config.
            config = let
              cnfPrefix = "${package.pname}-with-pkcs11";
              originalMkKeyValue = lib.generators.mkKeyValueDefault {} " = ";
              mkKeyValue = k: v: let
                stripped = stripOrder k;
              in
                if stripped == ".include" then
                  ".include ${v}"
                else
                  originalMkKeyValue stripped v;
            in
            writeText "${cnfPrefix}.openssl.cnf" (lib.generators.toINIWithGlobalSection {
              inherit mkKeyValue;
              listsAsDuplicateKeys = true;
            } {
              globalSection = {
                ${addOrder 10 confName} = "openssl_init";
                ${addOrder 11 ".include"} = "${openssl.out}/etc/ssl/openssl.cnf";
              };

              sections = {
                openssl_init = {}
                  // (lib.optionalAttrs enableLegacyEngine (addOrderToAttrs 10 { engines = "engine_section"; }))
                  // (lib.optionalAttrs enableProvider (addOrderToAttrs 11 {providers = "provider_section"; }));
              } // (lib.optionalAttrs enableLegacyEngine {
                engine_section = {
                  ${engineName} = "${engineName}_engine_section";
                };
                "${engineName}_engine_section" = {
                  ${addOrder 10 "engine_id"} = engineName;
                  ${addOrder 11 "dynamic_path"} = "${libp11}/lib/engines/libpkcs11.so";
                  ${addOrder 12 "MODULE_PATH"} = pkcs11Module.path;
                  ${addOrder 99 "init"} = 1;
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
          in symlinkJoin {
            name = "${package.pname}-with-pkcs11";
            paths = [ package ];
            buildInputs = [ makeWrapper ];
            postBuild = ''
              find -L $out/bin -type f | while read program; do
                wrapProgram "$program" --set OPENSSL_CONF ${config}
              done
            '';
          };
        };
      });

      tpm2-pkcs11 = tpm2-pkcs11.overrideAttrs (package: with final; {
        passthru = (package.passthru or {}) // {
          pkcs11Module = {
            path = "${tpm2-pkcs11}/lib/libtpm2_pkcs11.so";
            options = {};
          };
        };
      });

      yubico-piv-tool = yubico-piv-tool.overrideAttrs (package: with final; {
        passthru = (package.passthru or {}) // {
          pkcs11Module = {
            path = "${yubico-piv-tool}/lib/libykcs11.so";
            options = {
              pkcs11-module-login-behavior = "never";
              pkcs11-module-quirks = "no-deinit";
            };
          };
        };
      });
    };
  };
}

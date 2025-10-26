{
  description = "Add support for PKCS#11 smartcards to various Nix packages";
  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    inputs@{
      self,
      flake-parts,
      nixpkgs,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      flake = {
        nixosModules.default = import ./module.nix self;
        overlays.default = import ./overlay.nix self;
        version = "1.2.0";
      };

      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      perSystem =
        {
          config,
          system,
          pkgs,
          final,
          lib,
          ...
        }:
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [
              self.overlays.default
            ];
            config = { };
          };

          devShells.default =
            with pkgs;
            mkShell {
              name = "nixpkcs-dev";
              packages = [ shellcheck ];
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
              inherit (pkgs.tpm2-pkcs11.abrmd) pkcs11Module;
              baseKeyId = 256; # swtpm supports rather high IDs, we should test them...
              extraKeypairOptions = {
                token = "nixpkcs";
              };
              extraMachineOptions =
                { config, ... }:
                {
                  virtualisation.tpm.enable = true;
                  nixpkcs.tpm2.enable = true;
                  users.users."nebula-nixpkcs" = lib.mkIf (config.services.nebula.networks.nixpkcs.enable or false) {
                    extraGroups = [ "tss" ];
                  };
                };
            };
            nginxTest = pkgs.callPackage ./nixos/tests/nginx.nix {
              inherit self nixpkgs;
              inherit (pkgs.tpm2-pkcs11.abrmd) pkcs11Module;
              extraKeypairOptions = {
                token = "nixpkcs";
              };
              extraMachineOptions =
                { config, ... }:
                {
                  virtualisation.tpm.enable = true;
                  nixpkcs.tpm2.enable = true;
                  users.users.nginx = {
                    extraGroups = [ "tss" ];
                  };
                };
            };
          };

          packages = {
            inherit (pkgs)
              nebula
              openssl
              opensc
              pkcs11-provider
              nss_latest
              yubico-piv-tool
              tpm2-pkcs11
              yubihsm-shell
              ;
          };
        };
    };
}

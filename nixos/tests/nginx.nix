{
  lib,
  testers,
  openssl,
  curl,
  nginx,
  pkgs,
  self,
  nixpkgs,
  pkcs11Module,
  extraKeypairOptions,
  extraMachineOptions ? { },
}:

let
  soPinFile = "/etc/so.pin";
  pinFile = "/etc/user.pin";
  extraEnv = pkcs11Module.mkEnv { };

  storeInitHook = pkgs.writeShellScript "store-init" ''
    chown -R nginx:nginx "$NIXPKCS_STORE_DIR" || true
  '';

  mkNode =
    {
      name,
      extraConfig ? { },
    }:
    lib.mkMerge [
      (
        { config, ... }:
        {
          imports = [
            self.nixosModules.default
          ];

          security.pkcs11 = {
            enable = true;
            keypairs = {
              ${name} = lib.recursiveUpdate {
                enable = true;
                inherit pkcs11Module extraEnv storeInitHook;
                id = 244837814094590; # 0xDEADBEEFCAFE
                debug = true;
                keyOptions = {
                  algorithm = "RSA";
                  type = "3072";
                  usage = [
                    "sign"
                    "derive"
                  ];
                  inherit soPinFile;
                };
                certOptions = {
                  serial = "09f91102";
                  subject = "C=US/ST=California/L=Carlsbad/O=nixpkcs/CN=nixpkcs.local";
                  extensions = [
                    "v3_ca"
                    "keyUsage=critical,nonRepudiation,keyCertSign,digitalSignature,cRLSign"
                    "subjectAltName=DNS:nixpkcs.local"
                  ];
                  validityDays = 14;
                  renewalPeriod = 7;
                  inherit pinFile;
                  writeTo = "/etc/keys/nixpkcs.local.crt";
                };
              } extraKeypairOptions;
            };
          };

          system.activationScripts.initTest.text = ''
            if [ ! -f ${lib.escapeShellArg pinFile} ]; then
              echo -n 22446688 > ${lib.escapeShellArg pinFile}
              chmod 0640 ${lib.escapeShellArg pinFile}
              chown nginx:nginx ${lib.escapeShellArg pinFile} || true
            fi
            if [ ! -f ${lib.escapeShellArg soPinFile} ]; then
              # If we are logging in as the user, place the user PIN in the SO PIN file.
              ${
                if config.security.pkcs11.keypairs.${name}.keyOptions.loginAsUser then
                  ''
                    ln -s ${lib.escapeShellArg pinFile} ${lib.escapeShellArg soPinFile}
                  ''
                else
                  ''
                    echo -n 11335577 > ${lib.escapeShellArg soPinFile}
                    chmod 0600 ${lib.escapeShellArg soPinFile}
                  ''
              }
            fi
            mkdir -p /etc/keys
          '';

          services.nginx = {
            enable = true;
            package = openssl.withPkcs11Module {
              inherit pkcs11Module;
              package = nginx;
              confName = "nginx";
              passthru = {
                inherit (nginx) modules;
              };
            };
            recommendedOptimisation = true;
            recommendedTlsSettings = true;
            recommendedProxySettings = true;
            recommendedGzipSettings = true;

            appendConfig = ''
              ${lib.concatMapStringsSep "\n" (x: "env ${x};") (lib.attrNames extraEnv)}
            '';

            virtualHosts."nixpkcs.local" = {
              forceSSL = true;
              sslCertificate = "/etc/keys/nixpkcs.local.crt";
              sslCertificateKey = pkgs.pkcs11-provider.uri2pem config.security.pkcs11.keypairs.${name}.uri;
              locations."/" = {
                root = ./nginx/root;
              };
            };
          };

          networking.hosts = {
            "127.0.0.1" = [ "nixpkcs.local" ];
          };

          environment = {
            systemPackages = [
              openssl
              curl
            ];
          };

          systemd.services."nginx" = {
            environment = extraEnv;
            serviceConfig = {
              # For accessing the TPM2 database.
              ProtectSystem = lib.mkForce false;

              # For accessing the TPM2 device.
              PrivateDevices = lib.mkForce false;
            };
          };
        }
      )
      extraConfig
      extraMachineOptions
    ];
in
testers.runNixOSTest {
  name = "nixpkcs-test-nginx";

  nodes.nginx = mkNode {
    name = "nginx";
  };

  testScript = ''
    nginx.start()

    # Wait for the keys to exist.
    nginx.wait_until_succeeds('openssl x509 -in /etc/keys/nixpkcs.local.crt -noout -subject | grep -q "nixpkcs.local"')

    # It should be in nixpkcs-uri too.
    nginx.succeed("nixpkcs-uri | tee /dev/stderr | grep -qE '^nginx[[:space:]]+pkcs11:.*?;?id=%DE%AD%BE%EF%CA%FE(;|$)'")

    # Wait for the webserver to come up, and make sure it's reliable thereafter
    nginx.succeed('systemctl restart nginx')
    cmd = 'curl --cacert /etc/keys/nixpkcs.local.crt https://nixpkcs.local/index.html | tee /dev/stderr | grep "Hello, nixpkcs!"'
    nginx.wait_until_succeeds(cmd)
    for i in range(100):
      nginx.succeed(cmd)
  '';
}

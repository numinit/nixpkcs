{ lib
, testers
, nebula
, nss_latest
, openssl
, pkgs
, self
, nixpkgs
}:

let
  # We'll need to be able to trade cert files between nodes via scp.
  inherit (import "${nixpkgs}/nixos/tests/ssh-keys.nix" pkgs)
    snakeOilPrivateKey snakeOilPublicKey;

  sshOpts = "-oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oIdentityFile=/root/.ssh/id_snakeoil";

  nssPin = "/etc/softokn.pin";
  nssDir = "/etc/softokn";
  nssLibEnv = {
    NSS_LIB_PARAMS = "configDir=${nssDir}";
  };

  mkNode = { name, realIp, staticHostMap ? null, extraConfig ? {} }: lib.mkMerge [
    ({ config, ... }: {
      disabledModules = ["services/networking/nebula.nix"];
      imports = [
        self.nixosModules.default
        ./nixos/modules/services/networking/nebula.nix
      ];
      networking = {
        hostName = name;
        interfaces.eth1 = {
          ipv4.addresses = lib.mkForce [{
            address = realIp;
            prefixLength = 24;
          }];
          useDHCP = false;
        };
      };

      nixpkcs = {
        enable = true;
        keypairs = {
          ${name} = {
            enable = true;
            inherit (nss_latest) pkcs11Module;
            token = "NSS Certificate DB";
            id = 1;
            slot = 2;
            extraEnv = nssLibEnv;
            keyOptions = {
              algorithm = "EC";
              type = "secp256r1";
              usage = ["sign" "derive" "decrypt" "wrap"];
              soPinFile = nssPin;
              loginAsUser = true;
            };
            certOptions = {
              serial = "09f91102";
              subject = "C=US/ST=California/L=Carlsbad/O=nixpkcs/CN=NixOS User ${name}'s Certificate";
              extensions = [
                # optional, but a good thing to test
                "v3_ca"
                "keyUsage=critical,nonRepudiation,keyCertSign,digitalSignature,cRLSign"
              ];
              validityDays = 14;
              renewalPeriod = 7;
              pinFile = nssPin;
              writeTo = "/home/${name}/${name}.crt";
            };
          };
        };
      };

      system.activationScripts.initTest.text = ''
        if [ ! -d /root/.ssh ]; then
          mkdir -p /root/.ssh
          chown 700 /root/.ssh
          cat ${lib.escapeShellArg snakeOilPrivateKey} > /root/.ssh/id_snakeoil
          chown 600 /root/.ssh/id_snakeoil
        fi

        if [ ! -f ${nssPin} ]; then
          echo -n 22446688 > ${nssPin}
          chmod 0640 ${nssPin}
          chown root:nebula-nixpkcs ${nssPin} || true
        fi

        if [ ! -d ${nssDir} ]; then
          mkdir -p ${nssDir}
          ${nss_latest.tools}/bin/certutil -N -d ${nssDir} -f ${nssPin} >&2
          chown -R nebula-nixpkcs:nebula-nixpkcs ${nssDir} || true
          echo "Generated softokn store for ${name}" >&2
        fi

        if [ ! -d /etc/nebula ]; then
          mkdir /etc/nebula

          # Useful in the scripts.
          echo ${lib.escapeShellArg config.nixpkcs.keypairs.${name}.uri} > /etc/nebula/${name}.key
          chown -R nebula-nixpkcs:nebula-nixpkcs /etc/nebula || true
        fi

        ${lib.optionalString ((config.nixpkcs.keypairs.ca.uri or null) != null) ''
          if [ ! -f /etc/nebula/ca.key ]; then
            echo ${lib.escapeShellArg config.nixpkcs.keypairs.ca.uri} > /etc/nebula/ca.key
            chown -R nebula-nixpkcs:nebula-nixpkcs /etc/nebula || true
          fi
        ''}
      '';

      services.openssh.enable = true;

      users.users = {
        ${name}.isNormalUser = true;
        root.openssh.authorizedKeys.keys = [ snakeOilPublicKey ];
      };

      environment = {
        systemPackages = [ nebula nss_latest.tools openssl ];
        variables = nssLibEnv;
      };
    })
    (lib.mkIf (staticHostMap != null)
      ({ config, ... }: {
        services.nebula.networks.nixpkcs = {
          # Note that these paths won't exist when the machine is first booted.
          enable = lib.mkDefault true;
          ca = "/etc/nebula/ca.crt";
          cert = "/etc/nebula/${name}.crt";
          key = config.nixpkcs.keypairs.${name}.uri;
          listen = {
            host = "0.0.0.0";
            port = 4242;
          };
          isLighthouse = true;
          lighthouses = builtins.attrNames staticHostMap;
          inherit staticHostMap;
          firewall = {
            outbound = [ { port = "any"; proto = "any"; host = "any"; } ];
            inbound = [ { port = "any"; proto = "any"; host = "any"; } ];
          };
        };

        # So we pass down NSS lib environment variables to Nebula.
        systemd.services."nebula@nixpkcs" = {
          environment = nssLibEnv;
          serviceConfig = {
            LockPersonality = lib.mkForce false;
          };
        };
      })
    )
    extraConfig
  ];
in testers.runNixOSTest {
  name = "nixpkcs-test";

  nodes = {
    # First participant.
    alice = mkNode {
      name = "alice";
      realIp = "192.168.1.1";
      staticHostMap = { "10.32.0.2" = [ "192.168.1.2:4242" ]; };
    };

    # Second participant.
    bob = mkNode {
      name = "bob";
      realIp = "192.168.1.2";
      staticHostMap = { "10.32.0.1" = [ "192.168.1.1:4242" ]; };
    };

    # The CA.
    charlie = mkNode {
      name = "charlie";
      realIp = "192.168.1.100";
    };

    # Hintjens, 2015
    mallory = mkNode {
      name = "mallory";
      realIp = "192.168.1.200";
      staticHostMap = {
        "10.32.0.1" = [ "192.168.1.1:4242" ];
        "10.32.0.2" = [ "192.168.1.2:4242" ];
      };
      extraConfig = {
        nixpkcs = {
          enable = true;
          keypairs = {
            ca = {
              enable = true;
              inherit (nss_latest) pkcs11Module;
              token = "NSS Certificate DB";
              id = 2;
              slot = 2;
              extraEnv = nssLibEnv;
              keyOptions = {
                algorithm = "EC";
                type = "secp256r1";
                usage = ["sign" "derive" "decrypt" "wrap"];
                soPinFile = nssPin;
                loginAsUser = true;
              };
              certOptions = {
                serial = "66666666";
                subject = "C=US/ST=California/L=Carlsbad/O=nixpkcs/CN=Mallory's Super Legit CA";
                validityDays = 3650;
                pinFile = nssPin;
                writeTo = "/home/mallory/ca.crt";
              };
            };
          };
        };
      };
    };
  };

  testScript =
    ''
      # Boot them all up.
      for machine in (alice, bob, charlie):
        machine.start()

      # Wait for the keys to exist.
      for machine in (alice, bob, charlie):
        machine.wait_until_succeeds('openssl x509 -in /home/{0}/{0}.crt -noout -subject | grep -q "NixOS User {0}\'s Certificate"'.format(machine.name))

      # Charlie is the root of trust.
      charlie.succeed('nebula-cert ca -curve P256 -name charlie -ips 10.32.0.0/16 -pkcs11 "$(</etc/nebula/charlie.key)" -out-crt /etc/nebula/charlie.crt')

      # Sign Alice and Bob's certs.
      for idx, machine in enumerate((alice, bob)):
        machine.succeed(
          'nebula-cert keygen -curve P256 -pkcs11 "$(</etc/nebula/{0}.key)" -out-pub /etc/nebula/{0}.pub'.format(machine.name),
          'scp ${sshOpts} /etc/nebula/{0}.pub root@192.168.1.100:/etc/nebula/{0}.pub'.format(machine.name)
        )
        charlie.succeed(
          'cat /etc/nebula/charlie.crt && nebula-cert sign -ca-crt /etc/nebula/charlie.crt -in-pub /etc/nebula/{0}.pub -out-crt /etc/nebula/{0}.crt -name {0} -pkcs11 "$(</etc/nebula/charlie.key)" -ip 10.32.0.{1}/16'.format(machine.name, idx + 1)
        )
        machine.succeed(
          'scp ${sshOpts} 192.168.1.100:/etc/nebula/charlie.crt /etc/nebula/ca.crt',
          'scp ${sshOpts} 192.168.1.100:/etc/nebula/{0}.crt /etc/nebula/{0}.crt'.format(machine.name),
          'chown -R nebula-nixpkcs:nebula-nixpkcs /etc/nebula /etc/softokn'
        )

      # No more need for Charlie, he's signed the certs he needed to.
      charlie.shutdown()

      # Enter Mallory
      mallory.start()
      for machine in (mallory,):
        machine.wait_until_succeeds('openssl x509 -in /home/{0}/{0}.crt -noout -subject | grep -q "NixOS User {0}\'s Certificate"'.format(machine.name))
        machine.wait_until_succeeds('openssl x509 -in /home/{0}/ca.crt -noout -subject | grep -q "Mallory\'s Super Legit CA"'.format(machine.name))

      # Mallory wants access to Alice and Bob's network but doesn't have the key.
      mallory.succeed(
        'nebula-cert keygen -curve P256 -pkcs11 "$(</etc/nebula/mallory.key)" -out-pub /etc/nebula/mallory.pub',
        'nebula-cert ca -curve P256 -name ca -ips 10.32.0.0/16 -pkcs11 "$(</etc/nebula/ca.key)" -out-crt /etc/nebula/ca.crt',
        'nebula-cert sign -ca-crt /etc/nebula/ca.crt -in-pub /etc/nebula/mallory.pub -out-crt /etc/nebula/mallory.crt -name mallory -pkcs11 "$(</etc/nebula/mallory.key)" -ip 10.32.0.3/16',
        'chown -R nebula-nixpkcs:nebula-nixpkcs /etc/nebula'
      )

      # Reboot all the remaining hosts.
      for machine in (alice, bob, mallory):
        machine.shutdown()
        machine.start()
     
      # Wait for Nebula to come up.
      for machine in (alice, bob, mallory):
        machine.wait_for_unit('nebula@nixpkcs.service')

      # Alice can ping Bob but not Mallory.
      alice.succeed("ping -c5 10.32.0.2")
      alice.fail("ping -c5 10.32.0.3")

      # Bob can ping Alice but not Mallory.
      bob.succeed("ping -c5 10.32.0.1")
      bob.fail("ping -c5 10.32.0.3")

      # Mallory can ping neither Alice nor Bob.
      mallory.fail("ping -c5 10.32.0.1")
      mallory.fail("ping -c5 10.32.0.2")
    '';
}

# nixPKCS

_Version 1.1.2_

**Ever wanted all your private keys to live in hardware tokens?** Whether that's a TPM or a Yubikey, [PKCS#11](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
has been one of the [handful](https://developers.yubico.com/PGP/) [of](https://developers.yubico.com/PIV/) [standards](https://developers.yubico.com/WebAuthn/) used to perform
strong authentication with smartcard-compatible devices.

**nixPKCS** provides passthrus and patches on a handful of packages to facilitate the use of PKCS#11 tokens in applications that do not ordinarily support them.

## Features

- Declaratively generate and renew keys in hardware tokens like TPM and Yubikey
- Automatically create self-signed certificates as a record of key generation
- Generate and manage PKCS#11 URIs as easily as anything else in your Nix config
- Inject support for PKCS#11 secrets into many programs linked with OpenSSL 3
- Patch programs that lack PKCS#11 support with an overlay

## Changelog

- 1.1.2
    - Automatically inject default provider-specific environment variables into wrappers so `system.environment` doesn't have to change to use tools
- 1.1.1
    - Support `<provider>.openssl` and `<provider>.opensc` passthrus
    - Support pkcs11-provider's debug environment variables with the OpenSSL wrapper
- 1.1.0: Many new features.
    - **Fully declarative TPM2 and NSS store initialization!** You now don't need to do anything imperative to initialize a TPM2 or NSS store using nixpkcs.
    - **Nginx and Nebula support**, featuring integration tests with TPM2 and NSS
        - Note that first requests to nginx may cause a dbus timeout until the key is loaded, but subsequent requests are fast
    - New store initialization hook
    - Updated rekeying hook to take the key name in $1
- 1.0: Initial release

## Supported PKCS#11 consumers

These consumers are supported via a wrapper accessible via `withPkcs11Module`.

|Package|Passthru|Description|
|:------|:-------|:----------|
|`openssl`|withPkcs11Module|Wraps any OpenSSL-linked application with a special OPENSSL_CONF enabling the pkcs11-provider OpenSSL provider or the p11-kit OpenSSL engine. Outputs a derivation created with symlinkJoin, `${name}-with-pkcs11`.|
|`opensc`|withPkcs11Module|Wraps `pkcs11-tool` with the given `pkcs11Module`.|

## Patched packages

These packages have PKCS#11 support added via a patch.

- `nebula`: Added PKCS#11 support to version 1.9.3
- `tpm2-pkcs11`: Support shared secret (Diffie-Hellman) derivation, and disable FAPI warnings

## Added packages

These packages were added:

- `pkcs11-provider.uri2pem`: Converts a PKCS#11 URI to PEM.
    - Supports functor syntax: `pkcs11-provider.uri2pem "pkcs11:..."` produces a PEM file in the Nix store
      that corresponds to a PKCS#11 URI.

## Supported PKCS#11 providers

As of version 1.1.1, you can use the passthru syntax to automatically get an PKCS#11 consumer that uses a particular PKCS#11 module (for instance, `yubico-piv-tool.openssl` or `tpm2-pkcs11.opensc`).

- `yubico-piv-tool.pkcs11Module`
- `tpm2-pkcs11.pkcs11Module`
- `nss_latest.pkcs11Module`

## Quickstart: Key Management

- Add this flake's NixOS module to your imports: `imports = [ nixpkcs.nixosModules.default ]`
- Load this flake as an overlay with something like: `nixpkgs.overlays = [ nixpkcs.overlays.default ]`
- Choose your PKCS#11 module provider from the list above.
- Write keypair definitions
- Keys will automatically be generated!

### Example

Since a Nix config speaks a thousand words, here are examples for both Yubikey and TPM.
The Yubikey-specific config parts are commented below.

```nix
nixpkcs = {
  enable = true;
  pcsc = {
    enable = true;
  };
  keypairs = {
    my-key = {
      enable = true;

      # The PKCS#11 module to use.
      inherit (tpm2-pkcs11) pkcs11Module;
      # inherit (yubico-piv-tool) pkcs11Module;

      # Script that runs after initializing the store for the first time,
      # for tokens that require a state directory (TPM2, for example).
      # storeInitHook = pkgs.writeShellScript "store-init-hook" '''
      #   chown -R alice:users "$NIXPKCS_STORE_DIR"
      # ''

      # The token name. For TPM, this can be whatever you want, as long as it's consistent.
      # The default is `nixpkcs`; `pkcs11-tool --list-slots` will tell you for other tokens.
      # token = "nixpkcs"; 
      # token = "YubiKey PIV #123456"; 

      # The key ID.
      # For yubikey, note the key mapping:
      # https://developers.yubico.com/yubico-piv-tool/YKCS11/
      id = 1;

      # Not required for all tokens, but is for NSS.
      # slot = 2;

      # Automatically generated; generally you don't need to change the default.
      # If you need to access this, you can use `config.nixpkcs.my-key.uri` in your config.
      # uri = "pkcs11:token=...";

      # In case you want the fully RFC compliant version with no extra parameters.
      # p11kit requires this, but you shouldn't unless you really need it.
      # rfc7512Uri = "pkcs11:token=..."

      # Environment variables we should pass to the script.
      # Defaults to `pkcs11Module.mkEnv {}`. If overridden, make sure to include those.
      # extraEnv = { MY_ENV_VARIABLE = 42; };

      # Enables very verbose debug output.
      # debug = true;

      # Options for the private key.
      keyOptions = {
        # EC or RSA.
        algorithm = "EC";

        # The bits (for RSA) or the curve (for ECDSA).
        type = "secp256r1";

        # Options: sign, derive, decrypt, wrap
        usage = ["sign" "derive"];

        # Security Officer PIN. For the yubikey, this is the management token.
        # At least 8 digits, maybe more. For the Yubikey, it's a 40 char hex string.
        soPinFile = "/etc/mgmt.pin";

        # Warning! This will regenerate the key every day and at boot.
        # force = true;

        # Needed for the Yubikey, but not needed for TPM and NSS.
        # loginAsUser = false;
      };

      # Options for the cert.
      certOptions = {
        # Can be omitted for a random certificate serial.
        # serial = "09f91102";

        # The subject.
        subject = "C=US/ST=California/L=Carlsbad/O=nixpkcs/CN=My CA Cert";

        # Extensions to add.
        # Certificate authority:
        extensions = [
            "v3_ca"
            "keyUsage=critical,nonRepudiation,keyCertSign,digitalSignature,cRLSign"
        ];

        # Server certificate:
        # extensions = [
        #    "basicConstraints=critical,CA:FALSE"
        #    "keyUsage=critical,digitalSignature,keyEncipherment,keyAgreement"
        #    "extendedKeyUsage=serverAuth"
        #    "subjectAltName=DNS:example.com"
        # ];

        # Client certificate:
        # extensions = [
        #    "basicConstraints=critical,CA:FALSE"
        #    "keyUsage=critical,digitalSignature,keyEncipherment"
        #    "extendedKeyUsage=clientAuth"
        # ];

        # Certificate (and key) validity in days.
        validityDays = 365 * 3;

        # Number of days prior to expiration this key should be renewed and replaced.
        # Set to 0 to disable auto-renewal.
        # renewalPeriod = 14;

        # File containing the user PIN. Usually 8 digits but can be more.
        pinFile = "/etc/user.pin";

        # If provided, will write the certificate here.
        writeTo = "/home/alice/ca.crt";

        # Called whenever nixpkcs runs. Can be used to restart services. See the module documentation for examples.
        # rekeyHook = pkgs.writeShellScript "rekey-hook" ''
        # if [ "$2" == 'new' ]; then
        #   cat > "/home/alice/$1.crt"
        #   chown alice:alice "/home/alice/$1.crt"
        # fi
        # ''
      };
    };
  };
};
```

### NixOS module

To automatically manage keys, you will need to use the NixOS module.

|Option|Default|Description|Example|
|:-----|:------|:----------|:------|
|`nixpkcs.enable`|false|Enables automated key management|`nixpkcs.enable = true`|
|`nixpkcs.pcsc.enable`|false|Enables the PCSC smartcard daemon. You will need this for Yubikeys.|`nixpkcs.pcsc.enable = true`|
|`nixpkcs.pcsc.users`|[]|Sets the users that can access smartcards other than root.|`nixpkcs.pcsc.users = ["alice" "bob"]`|
|`nixpkcs.tpm2.enable`|false|Enables TPM2 and tpm2-abrmd (the [TPM Access Broker and Resource Daemon](https://github.com/tpm2-software/tpm2-abrmd)). You will obviously need this for TPM2.|`true`|
|`nixpkcs.keypairs.<name>`|N/A|Each keypair.|See above|

## Quickstart: Consuming a PKCS#11 module

Some packages need to be wrapped to support PKCS#11 keys. The `withPkcs11Module` interface lets you do this.

### OpenSSL wrapper: `openssl.withPkcs11Module`

- `pkcs11Module`: The PKCS#11 module. Usually `my-package.pkcs11Module`.
- `package`: The package to wrap. Defaults to `openssl.bin`.
- `confName`: The config name. Defaults to `"openssl_conf"`. (For instance, nodejs requires `nodejs_conf`).
- `engineName`: The name of the OpenSSL engine, if engines are enabled. (Default: `pkcs11`)
- `enableLegacyEngine`: True if we should enable `p11-kit` as an OpenSSL engine. (Default: false, since we prefer OpenSSL providers, which [are not deprecated, unlike engines](https://github.com/openssl/openssl/blob/master/README-ENGINES.md#deprecation-note)). **NOTE**: Enabling this _and_ the provider may cause strange things to happen.
- `extraEngineOptions`: Extra options to pass to the engine config.
- `providerName`: The name of the OpenSSL provider (Default: `pkcs11`)
- `enableProvider`: True if we should enable the OpenSSL provider. (Default: true)
- `extraProviderOptions`: Extra options to pass to the provider config. See [the docs](https://github.com/latchset/pkcs11-provider/blob/main/docs/provider-pkcs11.7.md#configuration).
- `debug`: Enables verbose logging.

### Example: Wrapping node.js

The following will produce a node.js with OPENSSL_CONF pointing to a config that uses `pkcs11-provider`:

```nix
openssl.withPkcs11Module {
    inherit (yubico-piv-tool) pkcs11Module;
    package = nodejs;
    confName = "nodejs_conf";
}
```

This wrapped nodejs can be invoked just like normal nodejs, except that reading PEM files containing references to PKCS#11 keys works now:

```bash
./result/bin/node -e "const crypto = require('node:crypto'); const fs = require('node:fs'); const privkey = crypto.createPrivateKey(fs.readFileSync('provider.pem').toString('ascii')); const sign = crypto.createSign('SHA256'); sign.update('hello, node'); sign.end(); console.log(sign.sign(privkey));"
<Buffer 30 65 02 31 00 f4 59 e7 69 3a a3 1e b4 6b 1b c7 b1 43 83 ba 6a 09 17 87 93 3b ee 5c 23 bf 48 c3 34 1d c9 f2 77 8f 40 a6 af 5d b4 10 fe 4e 5e 12 64 e2 ... 53 more bytes>
```

## Configuring a Yubikey

To do many interesting things with private keys, you might need a certificate authority.

Generally, a single level CA will be sufficient, though you can set up a multi tiered CA if you have multiple Yubikeys or certificate slots you'd like to use.

Leaf certificates will be for clients and servers. A single root certificate (or a root and intermediate) will be used for signing other certificates.

1. Configure your Yubikey using [ykman](https://search.nixos.org/packages?channel=unstable&from=0&size=50&sort=relevance&type=packages&query=yubikey-manager).
    1. Make sure the CCID interface is enabled.
        - Yubikey 4: `ykman config mode OTP+FIDO+CCID`.
        - Yubikey 5: `ykman config usb`
    2. Set `nixpkcs.enable = true`.
    3. Optionally set `nixpkcs.pcscUsers = ["your username"]` so the correct users can access the Yubikey as a smartcard.

2. Set up your [PIN, PUK (PIN Unlock Key), and Management Key](https://developers.yubico.com/PIV/Introduction/Admin_access.html) with **either** ykman or [yubico-piv-tool](https://search.nixos.org/packages?channel=unstable&from=0&size=50&sort=relevance&type=packages&query=yubico-piv-tool).
    - Both are in nixpkgs. ykman may be slightly easier, but yubico-piv-tool provides a few more options. Note the [defaults](https://developers.yubico.com/PIV/Introduction/Admin_access.html) for the PIN, PUK, and Management Key. Keep them in a safe place.
        - Management Key: `yubico-piv-tool -a set-mgm-key`
        - PIN: `yubico-piv-tool -a change-pin`
        - PUK: `yubico-piv-tool -a change-puk`
    - Take note of the [PIV certificate slots](https://developers.yubico.com/PIV/Introduction/Certificate_slots.html).
        - Use slot 9c for root certificate keys, as a PIN is always required. Use slots 9d/82-95 for any keys where a PIN is optional, like TLS web server or client keys.
    - Decide what kind of keys you want to generate.
        - I generally go for ECC P-384 or RSA 3072. Since my Yubikey's PIV application doesn't support RSA 3072, I stuck with P-384.

3. Add the keys you want to generate to your NixOS configuration.

4. Use the keys!

## Contributing

All contributions to this project are licensed under the terms of the GNU Lesser General Public License, version 3.

You are free to use this in commercial works; please open a PR if you make an improvement.

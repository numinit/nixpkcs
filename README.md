# nixPKCS

Store references to PKCS#11 secrets from hardware security tokens in the Nix store, and use them in programs linked with OpenSSL 3.

THIS REPOSITORY IS EXPERIMENTAL AND MAY BREAK AT ANY POINT!

**Ever wanted all your private keys to live in hardware tokens?** Whether that's a TPM or a Yubikey, [PKCS#11](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
has been one of the [handful](https://developers.yubico.com/PGP/) [of](https://developers.yubico.com/PIV/) [standards](https://developers.yubico.com/WebAuthn/) used to perform
strong authentication with smartcard-compatible devices.

**nixPKCS** provides passthrus and patches on a handful of packages to facilitate the use of PKCS#11 tokens in applications that do not ordinarily support them.

## Added passthrus

|Package|Passthru|Description|
|:------|:-------|:----------|
|`openssl`|withPkcs11Module|Wraps any OpenSSL-linked application with a special OPENSSL_CONF enabling the pkcs11-provider OpenSSL provider or the p11-kit OpenSSL engine. Outputs a derivation created with symlinkJoin, `${name}-with-pkcs11`.|
|`pkcs11-provider`|makePkcs11Pem|Takes a PKCS#11 URL and outputs a `-----BEGIN PKCS#11 PROVIDER URI-----` PEM file containing this PKCS#11 URL encoded as ASN.1.|

## Patched packages

- `nebula`: Added PKCS#11 support to version 1.9.3

## Supported PKCS#11 providers

- `yubico-piv-tool.pkcs11Module`
- `tpm2-pkcs11.pkcs11Module`

## Quickstart

- Load this flake as an overlay with something like: `nixpkgs.overlays = [ nixpkcs.overlays.default ]`
- Choose your PKCS#11 module provider from the list above.
- Wrap your package using `openssl.withPkcs11Module`.

### `openssl.withPkcs11Module`

- `pkcs11Module`: The PKCS#11 module. Usually `my-package.pkcs11Module`.
- `package`: The package to wrap. Defaults to `openssl.bin`.
- `confName`: The config name. Defaults to `"openssl_conf"`. (For instance, nodejs requires `nodejs_conf`).
- `engineName`: The name of the OpenSSL engine, if engines are enabled. (Default: `pkcs11`)
- `enableLegacyEngine`: True if we should enable `p11-kit` as an OpenSSL engine. (Default: false, since we prefer OpenSSL providers, which [are not deprecated, unlike engines](https://github.com/openssl/openssl/blob/master/README-ENGINES.md#deprecation-note)). **NOTE**: Enabling this _and_ the provider may cause strange things to happen.
- `extraEngineOptions`: Extra options to pass to the engine config.
- `providerName`: The name of the OpenSSL provider (Default: `pkcs11`)
- `enableProvider`: True if we should enable the OpenSSL provider. (Default: true)
- `extraProviderOptions`: Extra options to pass to the provider config. See [the docs](https://github.com/latchset/pkcs11-provider/blob/main/docs/provider-pkcs11.7.md#configuration).

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

## Generating a certificate authority

To do many interesting things with private keys, you might need a certificate authority.

Generally, a single level CA will be sufficient, though you can set up a multi tiered CA if you have multiple Yubikeys or certificate slots you'd like to use.

Leaf certificates will be for clients and servers. A single root certificate (or a root and intermediate) will be used for signing other certificates.

1. Configure your Yubikey using [ykman](https://search.nixos.org/packages?channel=unstable&from=0&size=50&sort=relevance&type=packages&query=yubikey-manager).
    1. Make sure the CCID interface is enabled.
        - Yubikey 4: `ykman config mode OTP+FIDO+CCID`.
        - Yubikey 5: `ykman config usb`
    2. Set `services.pcscd.enable = true`.
    3. Optionally create a polkit rule so the correct users can access the Yubikey as a smartcard. See the Appendix. This may be a module option at some point.

2. Set up your [PIN, PUK (PIN Unlock Key), and Management Key](https://developers.yubico.com/PIV/Introduction/Admin_access.html) with **either** ykman or [yubico-piv-tool](https://search.nixos.org/packages?channel=unstable&from=0&size=50&sort=relevance&type=packages&query=yubico-piv-tool).
    - Both are in nixpkgs. ykman may be slightly easier, but yubico-piv-tool provides a few more options. Note the [defaults](https://developers.yubico.com/PIV/Introduction/Admin_access.html) for the PIN, PUK, and Management Key. Keep them in a safe place.
        - Management Key: `yubico-piv-tool -a set-mgm-key`
        - PIN: `yubico-piv-tool -a change-pin`
        - PUK: `yubico-piv-tool -a change-puk`
    - Take note of the [PIV certificate slots](https://developers.yubico.com/PIV/Introduction/Certificate_slots.html).
        - Use slot 9c for root certificate keys, as a PIN is always required. Use slots 9d/82-95 for any keys where a PIN is optional, like TLS web server or client keys.
    - Decide what kind of keys you want to generate.
        - I generally go for ECC P-384 or RSA 3072. Since my Yubikey's PIV application doesn't support RSA 3072, I stuck with P-384.

3. Get a version of OpenSSL that supports PKCS#11.
    - Add `pkgs.openssl.withPkcs11Module { inherit (pkgs.yubico-piv-tool) pkcs11Module; }` to your systemPackages to get an OpenSSL that supports your Yubikey.

4. Create your root key, which will be used to sign a root certificate.
    - Note that the certificate subject you provide will be used to create a self-signed attestation certificate on the Yubikey, which may not be the final certificate you'd like.
    - `yubico-piv-tool -v -a generate -k -s 9c -A ECCP384 -H SHA384 -S 'C=US/ST=California/L=Carlsbad/O=aurb.is/OU=Keymaster/CN=aurb.is Root CA' --touch-policy=always --pin-policy=always --attestation`

5. Find out the PKCS#11 URI of your key, substituting its serial below:
    - `openssl storeutl -keys -text "pkcs11:serial=123456;object-type=private"`
    - The output will be something like: `pkcs11:model=YubiKey%20YK4;manufacturer=Yubico%20(www.yubico.com);serial=123456;token=YubiKey%20PIV%20%23123456;id=%02;object=Private%20key%20for%20Digital%20Signature;type=private`
    - Also save off the private key provider URI PEM, starting with `-----BEGIN PKCS#11 PROVIDER URI----`. This PEM file does not actually contain your key; it is simply a reference to the key.

6. Sign the root certificate.
    - `openssl req -provider pkcs11 -key "pkcs11:model=YubiKey%20YK4;manufacturer=Yubico%20(www.yubico.com);serial=123456;token=YubiKey%20PIV%20%23123456;id=%02;object=Private%20key%20for%20Digital%20Signature;type=private" -new -x509 -sha384 -extensions v3_ca -subj '/C=US/ST=California/L=Carlsbad/O=aurb.is/OU=Keymaster/CN=aurb.is Root CA' -days $((365*5)) -addext 'keyUsage=critical,nonRepudiation,keyCertSign,digitalSignature,cRLSign' -outform PEM -out ca.crt`
    - Enter your Management Key and PIN, and touch the Yubikey to complete the signature

7. Import the certificate back onto the Yubikey.
    - `ykman piv certificates import 9c --verify ca.crt`
    - This will allow you to retrieve it later if you lose it somehow but still have the Yubikey.

8. Repeat steps 4-7 for any certificates you want to sign. Here is how to make a CSR for a handful of usecases:
    - Sub CA: `openssl req -provider pkcs11 -key "pkcs11:model=YubiKey%20YK4;manufacturer=Yubico%20(www.yubico.com);serial=123456;token=YubiKey%20PIV%20%23123456;id=%04;object=Private%20key%20for%20Card%20Authentication;type=private" -new -extensions v3_ca -subj '/C=US/ST=California/L=Carlsbad/O=aurb.is/OU=Keymaster/CN=aurb.is Sub CA #1234' -addext 'keyUsage=critical,nonRepudiation,keyCertSign,digitalSignature,cRLSign' -outform PEM -out subCA.csr`
    - Server: `openssl req -provider pkcs11 -key "pkcs11:model=YubiKey%20YK4;manufacturer=Yubico%20(www.yubico.com);serial=123456;token=YubiKey%20PIV%20%23123456;id=%04;object=Private%20key%20for%20Card%20Authentication;type=private" -new -subj '/C=US/ST=California/L=Carlsbad/O=aurb.is/OU=Keymaster/CN=foo.aurb.is' -addext 'basicConstraints=critical,CA:FALSE' -addext 'keyUsage=critical,digitalSignature,keyEncipherment,keyAgreement' -addext 'extendedKeyUsage=serverAuth' -addext 'subjectAltName=DNS:foo.aurb.is' -outform PEM -out server.csr`
    - Client: `openssl req -provider pkcs11 -key "pkcs11:model=YubiKey%20YK4;manufacturer=Yubico%20(www.yubico.com);serial=123456;token=YubiKey%20PIV%20%23123456;id=%04;object=Private%20key%20for%20Card%20Authentication;type=private" -new -subj '/C=US/ST=California/L=Carlsbad/O=aurb.is/OU=Keymaster/CN=bar.aurb.is' -addext 'basicConstraints=critical,CA:FALSE' -addext 'keyUsage=critical,digitalSignature,keyEncipherment' -addext 'extendedKeyUsage=clientAuth' -outform PEM -out client.csr`

9. And here is how to sign them:
    - `openssl ca -provider pkcs11 -keyfile privkey.pem -days $((2 * 365)) -in FILE.csr -out FILE.crt`
    - Note that you will want to use the file starting with `-----BEGIN PKCS#11 PROVIDER URI-----` saved from `openssl storeutl` as your key.

## Appendix

### Polkit rule for pcsc-lite

```nix
yubikeyPolkitRule = writeTextDir "share/polkit-1/rules.d/10-pcsc.rules" ''
  polkit.addRule(function (action, subject) {
    if (
      (action.id == "org.debian.pcsc-lite.access_pcsc" ||
        action.id == "org.debian.pcsc-lite.access_card") &&
      subject.user == "numinit"
    ) {
      return polkit.Result.YES;
    }
  });
'';

environment.systemPackages = [ yubikeyPolkitRule ];
```

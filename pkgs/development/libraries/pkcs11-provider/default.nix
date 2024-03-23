{ lib, stdenv, fetchFromGitHub, runCommandLocal
, openssl, nss, p11-kit
, opensc, gnutls, expect
, autoconf, autoconf-archive, automake, pkg-config, libtool
}:

stdenv.mkDerivation {
  pname = "pkcs11-provider";
  version = "0.4-pre";

  src = fetchFromGitHub {
    owner = "latchset";
    repo = "pkcs11-provider";
    rev = "f7d4da1e6fde5a8e0fd96eec4dfee8a4dddfbdf3";
    hash = "sha256-snM/aK6hjkg1gYTYifOomaMSN1yVqHLIWWqnsoUU3DQ=";
  };

  buildInputs = [ openssl nss p11-kit ];
  nativeBuildInputs = [ autoconf autoconf-archive automake pkg-config libtool ];

  # don't add SoftHSM to here: https://github.com/openssl/openssl/issues/22508
  nativeCheckInputs = [ p11-kit.bin opensc nss.tools gnutls openssl.bin expect ];

  postPatch = ''
    patchShebangs .

    # Makefile redirects to logfiles; make sure we can catch them.
    for name in softokn softhsm; do
      ln -s /dev/stderr tests/setup-$name.log
    done
  '';

  preConfigure = "autoreconf -fi";

  enableParallelBuilding = true;
  enableParallelInstalling = false;

  doCheck = true;

  passthru.makePkcs11Pem = uri: runCommandLocal "pkcs11.pem" { URI = uri; } ''
    set -euo pipefail
    export LC_ALL=C

    DESC="''${3:-PKCS#11 Provider URI v1.0}"

    DESC_HEX=$(printf '%s' "''${DESC}" | od -An -t x1)
    URI_HEX=$(printf '%s' "''${URI}"   | od -An -t x1)
    PEM_HEX=$(printf '30 82 %04x 1a 82 %04x %s 0c 82 %04x %s'  \
                     "$((''${#URI} + ''${#DESC} + 8))" \
                     "''${#DESC}" \
                     "''${DESC_HEX[*]}" \
                     "''${#URI}" \
                     "''${URI_HEX[*]}" \
                  | tr -d '\r\n\t ' \
                  | sed -e 's,\(.\{2\}\),\\x\1,g')
    {
        echo "-----BEGIN PKCS#11 PROVIDER URI-----"
        # shellcheck disable=SC2059 # printf should treat variable as format string
        printf "''${PEM_HEX}" | base64
        echo "-----END PKCS#11 PROVIDER URI-----"
    }  > $out
  '';

  meta = with lib; {
    homepage = "https://github.com/latchset/pkcs11-provider";
    description = "An OpenSSL 3.x provider to access hardware or software tokens using the PKCS#11 Cryptographic Token Interface";
    maintainers = with maintainers; [ numinit ];
    license = licenses.asl20;
    platforms = platforms.unix;
  };
}

/*
 * krypton.c  —  Multi-method file encryption / decryption / hashing tool
 *                Version 4.1
 *
 * ─── COMPILE — LINUX ─────────────────────────────────────────────────────────
 *
 *  1. Install OpenSSL development headers (if not already present):
 *       sudo apt install libssl-dev        # Debian / Ubuntu
 *       sudo dnf install openssl-devel     # Fedora / RHEL / CentOS
 *       sudo pacman -S openssl             # Arch Linux
 *
 *  2. Compile:
 *       gcc -Wall -Wextra -o krypton krypton.c -lssl -lcrypto
 *
 *  Alternative — Ubuntu/Debian without libssl-dev but with Node.js present:
 *       gcc -Wall -Wextra -o krypton krypton.c \
 *           -I/usr/include/node \
 *           /usr/lib/x86_64-linux-gnu/libcrypto.so.3
 *
 * ─── COMPILE — macOS ─────────────────────────────────────────────────────────
 *
 *  macOS ships LibreSSL (not OpenSSL) which lacks several algorithms.
 *  Install the real OpenSSL via Homebrew first:
 *
 *  1. Install Homebrew (if not already present):
 *       /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
 *
 *  2. Install OpenSSL:
 *       brew install openssl
 *
 *  3. Compile (adjust the version path if needed — check with: brew --prefix openssl):
 *       gcc -Wall -Wextra -o krypton krypton.c \
 *           -I$(brew --prefix openssl)/include \
 *           -L$(brew --prefix openssl)/lib \
 *           -lssl -lcrypto
 *
 *  Note: if you see "library not found for -lssl", confirm OpenSSL is installed:
 *       brew list openssl
 *
 * ─── COMPILE — WINDOWS ───────────────────────────────────────────────────────
 *
 *  Option A — MSYS2 / MinGW-w64  (recommended, closest to Linux workflow)
 *  -----------------------------------------------------------------------
 *  MSYS2 provides a full GCC toolchain and a native Windows OpenSSL build.
 *
 *  1. Download and install MSYS2 from https://www.msys2.org/
 *
 *  2. Open the "MSYS2 UCRT64" shell (Start menu → MSYS2 UCRT64), then:
 *       pacman -Syu                                 # update package database
 *       pacman -S mingw-w64-ucrt-x86_64-gcc \
 *                  mingw-w64-ucrt-x86_64-openssl    # install GCC + OpenSSL
 *
 *  3. Compile inside the UCRT64 shell:
 *       gcc -Wall -Wextra -o krypton.exe krypton.c -lssl -lcrypto
 *
 *  4. Run:
 *       ./krypton.exe -h
 *
 *  The resulting krypton.exe can be copied to any Windows machine that has
 *  the MSYS2 runtime DLLs (libssl-3-x64.dll, libcrypto-3-x64.dll,
 *  libgcc_s_seh-1.dll, libwinpthread-1.dll) in the same folder or on PATH.
 *  To find those DLLs: ldd krypton.exe | grep -v /c/Windows
 *
 *  Option B — WSL 2  (Windows Subsystem for Linux)
 *  -----------------------------------------------------------------------
 *  WSL 2 runs a real Linux kernel inside Windows. The Linux compile
 *  instructions above apply without modification.
 *
 *  1. Install WSL 2 (PowerShell as Administrator):
 *       wsl --install
 *     (installs Ubuntu by default; restart required)
 *
 *  2. Open the Ubuntu shell, then follow the Linux instructions above.
 *
 *  Option C — Visual Studio / MSVC  (advanced)
 *  -----------------------------------------------------------------------
 *  MSVC does not support C99 variable-length features and strsep() is a
 *  POSIX extension absent from the CRT.  A shim for strsep() is already
 *  included in this file (see the #ifdef _WIN32 block below).
 *
 *  1. Download and install Visual Studio 2022 (Community edition is free):
 *       https://visualstudio.microsoft.com/
 *     Select the "Desktop development with C++" workload.
 *
 *  2. Download a pre-built OpenSSL for Windows from one of:
 *       https://slproweb.com/products/Win32OpenSSL.html  (Win64 OpenSSL v3.x)
 *       https://vcpkg.io/  (vcpkg install openssl:x64-windows)
 *     Install to e.g. C:\OpenSSL-Win64
 *
 *  3. Open a "Developer Command Prompt for VS 2022" and compile:
 *       cl krypton.c ^
 *          /I "C:\OpenSSL-Win64\include" ^
 *          /link "C:\OpenSSL-Win64\lib\VC\x64\MD\libssl.lib" ^
 *                "C:\OpenSSL-Win64\lib\VC\x64\MD\libcrypto.lib" ^
 *          /out:krypton.exe
 *
 *  4. Copy the OpenSSL runtime DLLs next to krypton.exe:
 *       libssl-3-x64.dll   libcrypto-3-x64.dll
 *     (found in C:\OpenSSL-Win64\bin\)
 *
 * ─── LEGACY PROVIDER NOTE (all platforms) ───────────────────────────────────
 *
 *  OpenSSL 3.x moved DES, Blowfish, CAST5, and MD4 into a separate "legacy"
 *  provider module.  krypton loads it automatically at startup via:
 *    OSSL_PROVIDER_load(NULL, "legacy")
 *  The module file is named legacy.dll (Windows), legacy.dylib (macOS), or
 *  legacy.so (Linux) and is usually installed alongside OpenSSL itself.
 *  If the module is missing, modern ciphers still work; only the legacy ones
 *  (des, blowfish, cast5, md4) will report "not available in this build".
 *  Typical locations:
 *    Linux   : /usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so
 *    macOS   : $(brew --prefix openssl)/lib/ossl-modules/legacy.dylib
 *    Windows : C:\OpenSSL-Win64\lib\ossl-modules\legacy.dll
 *
 * ─── MODES ───────────────────────────────────────────────────────────────────
 *
 *   -e <method>    Encrypt   (requires -k, -i, -o)
 *   -d <method>    Decrypt   (requires -k, -i, -o)
 *   --hash <alg>   Hash      (requires -i; -o optional — saves hex to file)
 *   -h / --help    Show full help and examples
 *
 * ─── COMMAND-LINE FLAGS ──────────────────────────────────────────────────────
 *
 *   -e <method>   Cipher method name (see full list below)
 *   -d <method>   Same method name used for encryption
 *   -k <key>      Key / passphrase (format varies per method, see below)
 *   -i <file>     Input file path (any file type: binary, text, PDF, etc.)
 *   -o <file>     Output file path
 *   --hash <alg>  Hash algorithm name (one-way, no -k required)
 *
 * ─── KEY SYNTAX BY METHOD ────────────────────────────────────────────────────
 *
 *   Most cipher methods:
 *     -k "any passphrase"
 *     OpenSSL-backed ciphers derive a proper key via PBKDF2/SHA-256
 *     (10 000 iterations) from this passphrase + a random 16-byte salt.
 *     The salt is automatically prepended to the output file and read
 *     back transparently on decryption.
 *
 *   atbash, rot13:
 *     -k ""   (no key required; self-inverse)
 *
 *   polybe, bacon:
 *     -k ""   (no key required; encode with -e, decode with -d)
 *
 *   caesar:
 *     -k "N"  where N is an integer shift 0–255  (e.g. -k "13")
 *
 *   vigenere:
 *     -k "word"  alphabetic characters only, a–z or A–Z  (e.g. -k "lemon")
 *
 *   playfair:
 *     -k "keyword"  any word used to build the 5×5 Polybius key square
 *                   (e.g. -k "monarchy").  J is treated as I.
 *                   Input is alpha-only; X is inserted as padding per spec.
 *
 *   railfence:
 *     -k "N"  integer number of rails >= 2  (e.g. -k "3")
 *
 *   adfgvx:
 *     -k "SUBKEY:TRANSKEY"
 *       SUBKEY   = word used to build the 6×6 substitution grid (A–Z + 0–9)
 *       TRANSKEY = word used for columnar transposition
 *       Example: -k "DEUTSCH:ANGRIFF"
 *       Output characters are exclusively from the set {A, D, F, G, V, X}.
 *
 *   enigma:
 *     -k "R1:R2:R3:POS:PAIRS"
 *       R1 R2 R3 = rotor identifiers, left to right: I  II  III  IV  V
 *       POS      = 3-letter start positions (e.g. AAA or XKZ)
 *       PAIRS    = plugboard (Steckerbrett) pairs, space-separated (optional)
 *       Examples:
 *         -k "I:II:III:AAA:"             (no plugboard)
 *         -k "IV:I:V:XKZ:AB CD EF GH"   (4 plugboard pairs)
 *       Simulation details:
 *         - Rotors I–V with correct Wehrmacht wirings
 *         - Reflector B (Umkehrwalze B)
 *         - Authentic double-stepping anomaly implemented
 *         - Only A–Z processed; all other bytes pass through unchanged
 *         - Self-inverse: encrypting ciphertext with the same settings
 *           yields the original plaintext
 *
 *   vernam (One-Time Pad):
 *     -k "@/path/to/keyfile"
 *       The key must be a binary file at least as large as the input.
 *       The '@' prefix signals that the argument is a file path, not a
 *       passphrase.  The key file is XOR-ed byte-for-byte with the input.
 *       Self-inverse: same key file decrypts what it encrypts.
 *       WARNING: each key file must NEVER be reused; reuse breaks security.
 *
 *   xor:
 *     -k "passphrase"  (any non-empty string; key cycles over input bytes)
 *     Self-inverse: same operation encrypts and decrypts.
 *
 *   rc4:
 *     -k "passphrase"  (any string up to 256 characters)
 *     Self-inverse: same key decrypts.
 *
 *   chacha20:
 *     -k "passphrase"  (derived to 256-bit key via PBKDF2; unauthenticated)
 *
 *   chacha20-poly1305:
 *     -k "passphrase"  (AEAD — authenticated; detects any tampering)
 *
 *   3des / camellia-128 / camellia-256 / aria-128 / aria-256 / sm4:
 *     -k "passphrase"  (CBC mode, PKCS#7 padding, PBKDF2 key derivation)
 *
 *   aes-128 / aes-192 / aes-256:
 *     -k "passphrase"  (CBC mode, PKCS#7 padding, PBKDF2 key derivation)
 *
 *   aes-128-gcm / aes-192-gcm / aes-256-gcm:
 *     -k "passphrase"  (GCM mode — authenticated; detects any tampering)
 *     File format: [16-byte salt][12-byte nonce][ciphertext][16-byte tag]
 *
 * ─── ALL CIPHER METHODS ──────────────────────────────────────────────────────
 *
 *  Historical — Classical Antiquity (pure C):
 *    scytale     Scytale (~700 BC, Sparta). Columnar transposition on a staff.
 *                Key: integer column-width >= 2  (e.g. -k "4")
 *    atbash      Atbash cipher (~600 BC). Reverses alphabet A<->Z. Self-inverse.
 *                Key: none  (use -k "")
 *    affine      Affine cipher (classical antiquity). C = (a*P + b) mod 26.
 *                Key: "a,b" where a is coprime to 26  (e.g. -k "7,3")
 *    polybe      Polybius square (~200 BC). Maps letters to row/col digit pairs.
 *                Output is larger than input (text). -e encodes, -d decodes.
 *                Key: none  (use -k "")
 *    caesar      Caesar byte-shift cipher (~50 BC).
 *                Key: integer shift 0-255
 *
 *  Historical — Renaissance (pure C):
 *    trithemius  Trithemius cipher (Johannes Trithemius, 1508). Auto-key
 *                progressive shift using the tabula recta. Key: none.
 *    vigenere    Vigenere polyalphabetic cipher (Giovan Battista Bellaso, 1553).
 *                Key: alphabetic string a-z/A-Z
 *    porta       Porta cipher (Giovanni Battista della Porta, 1563). Reciprocal
 *                13-row alphabet table. Self-inverse.
 *                Key: any alphabetic string  (e.g. -k "secret")
 *    bacon       Bacon's cipher (Francis Bacon, 1605). Binary steganography:
 *                each letter -> 5 A/B characters. -e encodes, -d decodes.
 *                Key: none  (use -k "")
 *
 *  Historical — 19th Century (pure C):
 *    playfair    Playfair digraph cipher (Charles Wheatstone, 1854).
 *                First digraph cipher; used by British Army in WWI.
 *                Handles alpha text only; J treated as I; X used for padding.
 *                Key: any keyword
 *    beaufort    Beaufort cipher (Admiral Sir Francis Beaufort, 1857).
 *                Vigenère variant: C = (K - P) mod 26. Self-inverse.
 *                Key: alphabetic string a-z/A-Z  (e.g. -k "royalnavy")
 *    railfence   Rail Fence transposition cipher (US Civil War era).
 *                Zigzag write across N rails, read row by row.
 *                Key: integer number of rails >= 2
 *
 *  Historical — World War I (pure C):
 *    adfgvx      ADFGVX cipher (German Army, March 1918).
 *                6×6 Polybius substitution + columnar transposition.
 *                Handles A–Z and 0–9; output is {A,D,F,G,V,X} letters.
 *                Key: "SUBKEY:TRANSKEY"
 *    columnar    Columnar transposition (WWI / WWII). Writes text into rows,
 *                reads columns in keyword-sorted order.
 *                Key: any alphabetic keyword  (e.g. -k "ZEBRAS")
 * 
 *  Historical — World War II (pure C):
 *    double      Double transposition (SOE / Allied WWII field cipher).
 *                Two rounds of columnar transposition with two keys.
 *                Key: "KEY1:KEY2"  (e.g. -k "SECURITY:LONDON")
 *    enigma      Full Enigma machine simulation (Germany, 1923–1945).
 *                Rotors I–V, Reflector B, plugboard. Self-inverse.
 *                Key: "R1:R2:R3:POS:PAIRS"
 * 
 *  Historical — Other 20th Century Ciphers (pure C):
 *    foursquare  Four-Square cipher (Felix Delastelle, 1901). Four 5x5 grids.
 *                Key: "KEY1:KEY2"  (e.g. -k "EXAMPLE:KEYWORD")
 *    vernam      Vernam cipher / One-Time Pad (Gilbert Vernam, 1917).
 *                Proven information-theoretically secure (Shannon, 1949).
 *                Key must be a file path prefixed with '@'.
 *    rot13       ROT13 letter substitution (Usenet, ~1980). Self-inverse.
 *                Key: none  (use -k "")
 *    rot47       ROT47 (Usenet, ~1990s). Rotates all 94 printable ASCII chars
 *                by 47. Self-inverse. Key: none  (use -k "")
 *
 *  Modern stream ciphers (pure C):
 *    xor         XOR byte cipher. Self-inverse.
 *    rc4         RC4 stream cipher (Ron Rivest, 1987). Self-inverse.
 *
 *  Modern stream ciphers (OpenSSL):
 *    chacha20          ChaCha20 (Daniel J. Bernstein, 2008). Unauthenticated.
 *    chacha20-poly1305 ChaCha20 + Poly1305 MAC. Authenticated (AEAD). [*]
 *
 *  Block ciphers — CBC mode (OpenSSL, PKCS#7 padding, PBKDF2 key derivation):
 *    des          DES-CBC.        [BROKEN — 56-bit key, brute-forceable]
 *    blowfish     Blowfish-CBC.   [LEGACY — 64-bit block, SWEET32 risk]
 *    cast5        CAST5-CBC.      [LEGACY — 64-bit block, SWEET32 risk]
 *    3des         Triple-DES-EDE-CBC. [LEGACY — deprecated by NIST 2023]
 *    camellia-128 Camellia-128-CBC. ISO/IEC 18033-3, NESSIE-approved.
 *    camellia-256 Camellia-256-CBC. ISO/IEC 18033-3, NESSIE-approved.
 *    aria-128     ARIA-128-CBC. Korean national standard KS X 1213.
 *    aria-256     ARIA-256-CBC. Korean national standard KS X 1213.
 *    sm4          SM4-CBC. Chinese national standard GB/T 32907-2016.
 *    aes-128      AES-128-CBC. NIST FIPS 197.
 *    aes-192      AES-192-CBC. NIST FIPS 197.
 *    aes-256      AES-256-CBC. NIST FIPS 197. Recommended general-purpose.
 *
 *  Block ciphers — GCM mode / Authenticated Encryption (OpenSSL):  [*]
 *    aes-128-gcm  AES-128-GCM.
 *    aes-192-gcm  AES-192-GCM.
 *    aes-256-gcm  AES-256-GCM. Recommended — best security.
 *
 *  [*] Authenticated modes (AEAD) provide both confidentiality AND integrity.
 *      Any modification to the ciphertext is detected on decryption and
 *      causes an explicit error ("Authentication FAILED").
 *
 * ─── HASH ALGORITHMS (--hash mode) ──────────────────────────────────────────
 *
 *  All hash modes compute a digest and print it as a hex string to stdout.
 *  Optionally save to file with -o.  No key required.
 *
 *  Legacy (cryptographically broken — use only for compatibility):
 *    md4         MD4 (Ron Rivest, 1990).  128-bit / 32 hex chars.
 *                Predecessor of MD5; still used internally by NTLM/Windows.
 *                Requires OpenSSL legacy provider (loaded automatically).
 *    md5         MD5 (Ron Rivest, 1992).  128-bit / 32 hex chars.
 *    sha1        SHA-1 (NIST, 1995).      160-bit / 40 hex chars.
 *                Note: "sha" is accepted as an alias for sha1.
 *                SHA-0 (the withdrawn 1993 original) is not available in
 *                modern OpenSSL builds and is not supported.
 *
 *  SHA-2 family (NIST FIPS 180-4):
 *    sha224      SHA-224.  224-bit / 56 hex chars.
 *    sha256      SHA-256.  256-bit / 64 hex chars.  Recommended general use.
 *    sha384      SHA-384.  384-bit / 96 hex chars.
 *    sha512      SHA-512.  512-bit / 128 hex chars.
 *
 *  SHA-3 family (NIST FIPS 202 — Keccak):
 *    sha3-256    SHA3-256. 256-bit / 64 hex chars.
 *    sha3-512    SHA3-512. 512-bit / 128 hex chars.
 *
 *  BLAKE2 family:
 *    blake2b     BLAKE2b-512. 512-bit / 128 hex chars. Fast on 64-bit systems.
 *    blake2s     BLAKE2s-256. 256-bit / 64 hex chars.  Fast on 32-bit systems.
 *
 * ─── SECURITY NOTES ──────────────────────────────────────────────────────────
 *
 *  - For any new system, prefer aes-256-gcm or chacha20-poly1305.
 *    These are AEAD modes: they guarantee both confidentiality and integrity.
 *  - CBC modes (aes-128/192/256, camellia-*, aria-*, sm4, 3des) provide
 *    confidentiality only; a tampered ciphertext may decrypt without error.
 *  - Historical ciphers (atbash, caesar, vigenere, enigma, etc.) offer NO
 *    modern security. Use them only for educational or recreational purposes.
 *  - Vernam/OTP is the only cipher proven information-theoretically secure,
 *    but requires a truly random key as large as the message, used only once.
 *  - All OpenSSL-backed ciphers derive keys via PBKDF2-HMAC-SHA256 with a
 *    random 16-byte salt and 10 000 iterations, making brute-force harder.
 *  - rc4 has known statistical biases; avoid it for sensitive data.
 *  - 3des is deprecated by NIST (2023); included for legacy compatibility only.
 *
 * ─── EXAMPLES ────────────────────────────────────────────────────────────────
 *
 *  # Best modern security (authenticated)
 *  ./krypton -e aes-256-gcm        -k "P@ss!" -i doc.pdf    -o doc.enc
 *  ./krypton -d aes-256-gcm        -k "P@ss!" -i doc.enc    -o doc.pdf
 *
 *  # Fast modern security (authenticated)
 *  ./krypton -e chacha20-poly1305  -k "P@ss!" -i video.mp4  -o video.enc
 *  ./krypton -d chacha20-poly1305  -k "P@ss!" -i video.enc  -o video.mp4
 *
 *  # Enigma (self-inverse — same command decrypts)
 *  ./krypton -e enigma -k "I:II:III:AAA:AB CD" -i msg.txt   -o msg.enc
 *  ./krypton -e enigma -k "I:II:III:AAA:AB CD" -i msg.enc   -o msg.dec
 *
 *  # Vernam / One-Time Pad
 *  ./krypton -e vernam -k "@/secure/pad.bin"   -i msg.txt   -o msg.enc
 *  ./krypton -d vernam -k "@/secure/pad.bin"   -i msg.enc   -o msg.txt
 *
 *  # ADFGVX (WWI German cipher)
 *  ./krypton -e adfgvx -k "DEUTSCH:ANGRIFF"    -i msg.txt   -o msg.enc
 *  ./krypton -d adfgvx -k "DEUTSCH:ANGRIFF"    -i msg.enc   -o msg.txt
 *
 *  # Playfair
 *  ./krypton -e playfair -k "monarchy"          -i plain.txt -o cipher.txt
 *  ./krypton -d playfair -k "monarchy"          -i cipher.txt -o plain.txt
 *
 *  # Rail Fence (3 rails)
 *  ./krypton -e railfence -k "3"                -i plain.txt -o cipher.txt
 *  ./krypton -d railfence -k "3"                -i cipher.txt -o plain.txt
 *
 *  # Polybius square encoding
 *  ./krypton -e polybe  -k "" -i plain.txt      -o encoded.txt
 *  ./krypton -d polybe  -k "" -i encoded.txt    -o plain.txt
 *
 *  # Bacon binary steganography
 *  ./krypton -e bacon   -k "" -i plain.txt      -o bacon.txt
 *  ./krypton -d bacon   -k "" -i bacon.txt      -o plain.txt
 *
 *  # Hash a file (SHA-256)
 *  ./krypton --hash sha256   -i firmware.bin
 *  ./krypton --hash blake2b  -i archive.tar.gz  -o archive.b2
 *
 * ─────────────────────────────────────────────────────────────────────────────
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <math.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/provider.h>

/* ═══════════════════════════════════════════════════════════════════════════
   Constants
   ═══════════════════════════════════════════════════════════════════════════ */

#define CHUNK_SIZE    4096
#define SALT_LEN        16
#define GCM_TAG_LEN     16
#define GCM_IV_LEN      12
#define KDF_ITER     10000
#define MAX_KEY_BYTES   32
#define MAX_IV_BYTES    16

#ifdef _WIN32

/* ═══════════════════════════════════════════════════════════════════════════
   Implementation of strsep for Windows (MinGW / MSVC)
   Same behavior as version POSIX
   ═══════════════════════════════════════════════════════════════════════════ */

char *strsep(char **stringp, const char *delim) {
    char *start = *stringp;
    char *p;

    if (start == NULL)
        return NULL;

    // Find the first delim
    p = strpbrk(start, delim);
    if (p) {
        *p = '\0';
        *stringp = p + 1;
    } else {
        *stringp = NULL;
    }

    return start;
}

#endif

/* ═══════════════════════════════════════════════════════════════════════════
   Error helpers
   ═══════════════════════════════════════════════════════════════════════════ */

static void die(const char *msg)
{
    fprintf(stderr, "[ERROR] %s\n", msg);
    exit(EXIT_FAILURE);
}

static void openssl_die(const char *ctx)
{
    fprintf(stderr, "[ERROR] %s: ", ctx);
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}

/* ═══════════════════════════════════════════════════════════════════════════
   print_help
   ═══════════════════════════════════════════════════════════════════════════ */

static void print_help(const char *p)
{
    printf(
"+---------------------------------------------------------------------------+\n"
"|        krypton  --  file encryptor / decryptor / hasher  v0.8             |\n"
"+---------------------------------------------------------------------------+\n\n"
"USAGE\n"
"  %s -e <method>        -k <key> -i <input> -o <output>   # encrypt\n"
"  %s -d <method>        -k <key> -i <input> -o <output>   # decrypt\n"
"  %s --hash <algorithm>          -i <input> [-o <output>] # hash\n"
"  %s -h                                                   # help\n\n"
"OPTIONS\n"
"  -e <method>   Encrypt   -d <method>   Decrypt\n"
"  --hash <alg>  Hash (one-way, no decryption)\n"
"  -k <key>      Key / passphrase (see per-method notes)\n"
"  -i <file>     Input file        -o <file>  Output file\n\n"
"===========================================================================\n"
" HISTORICAL CIPHERS  (pure C, zero dependencies)\n"
"===========================================================================\n\n"
"  -- Classical Antiquity --------------------------------------------------\n\n"
"  scytale    Scytale transposition cipher  (~700 BC, Sparta)\n"
"             Wraps text around a staff; key is the number of columns.\n"
"             Key: integer column-width >= 2  (e.g. -k \"4\")\n\n"
"  atbash     Atbash cipher  (~600 BC, Hebrew, Biblical)\n"
"             Reverses the alphabet: A<->Z, B<->Y ...  Self-inverse.\n"
"             Key: none  (use -k \"\")\n\n"
"  affine     Affine cipher  (Antiquity, precise date unknown)\n"
"             Encrypts each letter as (a*x + b) mod 26.\n"
"             Key: \"a,b\"  (e.g. -k \"7,3\")  a must be coprime to 26.\n"
"             Valid a values: 1 3 5 7 9 11 15 17 19 21 23 25\n\n"
"  polybe     Polybius square  (~200 BC, Ancient Greece)\n"
"             Maps letters to row/column pairs in a 5x5 grid.\n"
"             Output is larger than input (text pairs: \"11\" \"12\" ...).\n"
"             Key: none  (use -k \"\")  |  -e encodes, -d decodes\n\n"
"  caesar     Caesar shift cipher  (~50 BC)\n"
"             Key: integer shift 0-255  (e.g. -k \"13\")\n\n"
"  -- Renaissance ----------------------------------------------------------\n\n"
"  trithemius Trithemius cipher  (Johannes Trithemius, 1508)\n"
"             Auto-key progressive shift: position i shifts by i mod 26.\n"
"             First printed book on cryptography (Polygraphia, 1508).\n"
"             Key: none  (use -k \"\")\n\n"
"  vigenere   Vigenere polyalphabetic cipher  (Giovan Battista Bellaso, 1553)\n"
"             Key: alphabetic string a-z/A-Z  (e.g. -k \"lemon\")\n\n"
"  porta      Porta cipher  (Giovanni Battista della Porta, 1563)\n"
"             Reciprocal 13-row alphabet table. Self-inverse.\n"
"             First book dedicated to cryptanalysis.\n"
"             Key: alphabetic string  (e.g. -k \"secret\")\n\n"
"  bacon      Bacon's cipher  (Francis Bacon, 1605)\n"
"             Steganographic binary encoding: each letter -> 5 A/B bits.\n"
"             Key: none  (use -k \"\")  |  -e encodes, -d decodes\n\n"
"  -- 19th Century ---------------------------------------------------------\n\n"
"  playfair   Playfair cipher  (Charles Wheatstone, 1854)\n"
"             First digraph cipher; used by British Army in WWI.\n"
"             Key: any word  (e.g. -k \"monarchy\")  |  alpha only in/out\n\n"
"  beaufort   Beaufort cipher  (Admiral Sir Francis Beaufort, 1857)\n"
"             Vigenere variant: C = (K - P) mod 26.  Self-inverse.\n"
"             Key: alphabetic string a-z/A-Z  (e.g. -k \"royalnavy\")\n\n"
"  railfence  Rail Fence transposition cipher  (US Civil War era)\n"
"             Writes text in zigzag across N rails, reads off row by row.\n"
"             Key: integer number of rails >= 2  (e.g. -k \"3\")\n\n"
"  -- World War I ----------------------------------------------------------\n\n"
"  adfgvx     ADFGVX cipher  (German Army, 1918)\n"
"             Polybius-like substitution over 6x6 grid + columnar transposition.\n"
"             Key: \"SUBKEY:TRANSKEY\"  (e.g. -k \"DEUTSCH:ANGRIFF\")\n"
"             Output letters are from the set A D F G V X.\n\n"
"  columnar   Columnar transposition cipher  (WWI / WWII)\n"
"             Writes text into rows, reads columns in keyword-sorted order.\n"
"             Key: alphabetic keyword  (e.g. -k \"ZEBRAS\")\n\n"
"  -- World War II ---------------------------------------------------------\n\n"
"  double     Double transposition cipher  (SOE / WWII field cipher)\n"
"             Two rounds of columnar transposition with two independent keys.\n"
"             Key: \"KEY1:KEY2\"  (e.g. -k \"SECURITY:LONDON\")\n\n"
"  enigma     Enigma machine simulation  (1923-1945, Wehrmacht/Kriegsmarine)\n"
"             Full simulation: 3 rotors (I-V), reflector B, plugboard.\n"
"             Self-inverse: same settings decrypt what they encrypt.\n"
"             Key format: \"R1:R2:R3:POS:PAIRS\"\n"
"               R1/R2/R3 = rotor numbers  I II III IV V  (left to right)\n"
"               POS      = 3-letter start positions  (e.g. AAA or XKZ)\n"
"               PAIRS    = plugboard pairs, space-separated  (e.g. AB CD EF)\n"
"             Examples:\n"
"               -k \"I:II:III:AAA:\"          (no plugboard)\n"
"               -k \"IV:I:V:XKZ:AB CD EF GH\" (4 plugboard pairs)\n"
"             Only A-Z processed; other bytes pass through unchanged.\n\n"
"  -- Other 20th Century Ciphers -------------------------------------------\n\n"
"  foursquare Four-Square cipher  (Felix Delastelle, 1901)\n"
"             Four 5x5 Playfair-like grids for digraph substitution.\n"
"             Key: \"KEY1:KEY2\"  (e.g. -k \"EXAMPLE:KEYWORD\")  |  alpha only\n\n"
"  vernam     Vernam cipher / One-Time Pad  (Gilbert Vernam, 1917)\n"
"             XOR with a key file of the same size as the input.\n"
"             Proven information-theoretically secure (Shannon, 1949).\n"
"             Key: @/path/to/keyfile  (e.g. -k \"@/secure/mykey.bin\")\n"
"             Self-inverse: same key file decrypts what it encrypts.\n\n"
"  rot13      ROT13 substitution  (Usenet, ~1980)  Self-inverse.\n"
"             Key: none  (use -k \"\")\n\n"
"  rot47      ROT47 substitution  (Usenet, ~1990s)  Self-inverse.\n"
"             Rotates all 94 printable ASCII characters (0x21 to 0x7E) by 47.\n"
"             Key: none  (use -k \"\")\n\n"
"===========================================================================\n"
" MODERN STREAM CIPHERS  (pure C)\n"
"===========================================================================\n\n"
"  xor        XOR byte cipher.  Key: any string.  Self-inverse.\n"
"  rc4        RC4 stream cipher.  Key: any string <= 256 chars.  Self-inverse.\n\n"
"===========================================================================\n"
" MODERN BLOCK CIPHERS  (OpenSSL, CBC mode + PKCS#7, PBKDF2 key derivation)\n"
"===========================================================================\n\n"
"  chacha20         ChaCha20 (unauthenticated)      Key: any passphrase\n"
"  chacha20-poly1305  ChaCha20+Poly1305  [AUTH *]   Key: any passphrase\n"
"  camellia-128     Camellia-128-CBC                Key: any passphrase\n"
"  camellia-256     Camellia-256-CBC                Key: any passphrase\n"
"  aria-128         ARIA-128-CBC                    Key: any passphrase\n"
"  aria-256         ARIA-256-CBC                    Key: any passphrase\n"
"  sm4              SM4-CBC (Chinese std)           Key: any passphrase\n"
"  3des             Triple-DES-EDE-CBC  [LEGACY]    Key: any passphrase\n"
"  aes-128          AES-128-CBC                     Key: any passphrase\n"
"  aes-192          AES-192-CBC                     Key: any passphrase\n"
"  aes-256          AES-256-CBC  (recommended)      Key: any passphrase\n"
"  aes-128-gcm      AES-128-GCM  [AUTH *]           Key: any passphrase\n"
"  aes-192-gcm      AES-192-GCM  [AUTH *]           Key: any passphrase\n"
"  aes-256-gcm      AES-256-GCM  [AUTH *] (best)    Key: any passphrase\n\n"
"  -- Legacy block ciphers (OpenSSL legacy provider, CBC mode) -------------\n\n"
"  des              DES-CBC  *** CRYPTOGRAPHICALLY BROKEN (56-bit key) ***\n"
"                   Key: any passphrase  |  included for legacy/educational use\n\n"
"  blowfish         Blowfish-CBC  [LEGACY -- 64-bit block, SWEET32 risk]\n"
"                   Key: any passphrase  |  variable key 32-448 bits\n\n"
"  cast5            CAST5-CBC  [LEGACY -- 64-bit block, SWEET32 risk]\n"
"                   Key: any passphrase  |  used in older PGP and SSH\n\n"
"  [*] Authenticated: decryption fails if the file was tampered with.\n\n"
"===========================================================================\n"
" HASH ALGORITHMS  (--hash mode -- one-way)\n"
"===========================================================================\n\n"
"  -- Legacy (broken -- for compatibility only) ----------------------------\n"
"  md4              MD4       128-bit  predecessor of MD5, used in NTLM\n"
"  md5              MD5       128-bit  broken since 2004\n"
"  sha / sha1       SHA-1     160-bit  deprecated; collision found 2017\n\n"
"  -- SHA-2 family (NIST FIPS 180-4) --------------------------------------\n"
"  sha224           SHA-224   224-bit / 56 hex chars\n"
"  sha256           SHA-256   256-bit / 64 hex chars  (recommended)\n"
"  sha384           SHA-384   384-bit / 96 hex chars\n"
"  sha512           SHA-512   512-bit / 128 hex chars\n\n"
"  -- SHA-3 family (NIST FIPS 202) ----------------------------------------\n"
"  sha3-256         SHA3-256  256-bit / 64 hex chars\n"
"  sha3-512         SHA3-512  512-bit / 128 hex chars\n\n"
"  -- BLAKE2 family -------------------------------------------------------\n"
"  blake2b          BLAKE2b   512-bit / 128 hex chars  (fast on 64-bit)\n"
"  blake2s          BLAKE2s   256-bit / 64 hex chars   (fast on 32-bit)\n\n"
"===========================================================================\n"
" EXAMPLES\n"
"===========================================================================\n\n"
"  # Best modern security\n"
"  %s -e aes-256-gcm       -k \"P@ss!\" -i doc.pdf    -o doc.enc\n"
"  %s -d aes-256-gcm       -k \"P@ss!\" -i doc.enc    -o doc.pdf\n\n"
"  # Enigma simulation (self-inverse -- same command decrypts)\n"
"  %s -e enigma -k \"I:II:III:AAA:AB CD\" -i msg.txt  -o msg.enc\n"
"  %s -e enigma -k \"I:II:III:AAA:AB CD\" -i msg.enc  -o msg.dec\n\n"
"  # Vernam / One-Time Pad\n"
"  %s -e vernam -k \"@/secure/pad.bin\"   -i msg.txt  -o msg.enc\n"
"  %s -d vernam -k \"@/secure/pad.bin\"   -i msg.enc  -o msg.txt\n\n"
"  # Playfair\n"
"  %s -e playfair -k \"monarchy\" -i plain.txt -o cipher.txt\n\n"
"  # ADFGVX\n"
"  %s -e adfgvx -k \"DEUTSCH:ANGRIFF\" -i plain.txt -o cipher.txt\n\n"
"  # Polybius (encoding)\n"
"  %s -e polybe  -k \"\" -i plain.txt -o encoded.txt\n"
"  %s -d polybe  -k \"\" -i encoded.txt -o plain.txt\n\n"
"  # Bacon steganography\n"
"  %s -e bacon   -k \"\" -i plain.txt -o bacon.txt\n"
"  %s -d bacon   -k \"\" -i bacon.txt -o plain.txt\n\n"
"  # Hash\n"
"  %s --hash sha256 -i firmware.bin\n\n",
    p,p,p,p, p,p,p,p,p,p,p,p,p,p,p,p,p,p);
}

/* ═══════════════════════════════════════════════════════════════════════════
   ███  HISTORICAL CIPHERS
   ═══════════════════════════════════════════════════════════════════════════ */

/* ───────────────────────────────────────────────────────────────────────────
   Shared transposition helpers
   ─────────────────────────────────────────────────────────────────────────── */

/* Read entire FILE into a malloc'd buffer; set *len to byte count. */
static uint8_t *read_all(FILE *in, size_t *len)
{
    uint8_t *buf = NULL; size_t n = 0, cap = 0; int ch;
    while ((ch = fgetc(in)) != EOF) {
        if (n + 1 > cap) {
            cap = cap ? cap * 2 : 256;
            uint8_t *nb = (uint8_t *)realloc(buf, cap);
            if (!nb) { free(buf); die("out of memory"); }
            buf = nb;
        }
        buf[n++] = (uint8_t)ch;
    }
    *len = n;
    return buf ? buf : (uint8_t *)calloc(1, 1);
}

/* Build sorted column order from keyword: order[i] = original column for
   the i-th column in sorted (alphabetical) keyword order. */
static int *keyword_order(const char *key, int ncols)
{
    int *order = (int *)malloc((size_t)ncols * sizeof(int));
    if (!order) die("out of memory");
    for (int i = 0; i < ncols; i++) order[i] = i;
    /* Stable sort: compare keyword chars, tie-break by original position */
    for (int i = 0; i < ncols - 1; i++)
        for (int j = i + 1; j < ncols; j++)
            if (toupper((unsigned char)key[order[i]]) >
                toupper((unsigned char)key[order[j]])) {
                int t = order[i]; order[i] = order[j]; order[j] = t;
            }
    return order;
}

/* KEY INSIGHT FOR RAGGED GRIDS
 * When tlen is not a multiple of ncols:
 *   nrows     = ceil(tlen / ncols)
 *   full_cols = tlen % ncols
 *
 * In the plain grid (written row by row), the last row has only
 * full_cols characters, occupying ORIGINAL columns 0 .. full_cols-1.
 * ORIGINAL columns full_cols .. ncols-1 are empty in the last row.
 *
 * Therefore:
 *   col_rows(col) = nrows     if col < full_cols  (or full_cols == 0)
 *   col_rows(col) = nrows-1   if col >= full_cols (and full_cols != 0)
 *
 * This is purely about ORIGINAL column indices, not sorted positions.
 */
#define COL_ROWS(col, nrows, full_cols) \
    (((full_cols) == 0 || (col) < (full_cols)) ? (nrows) : (nrows)-1)

/* Columnar encrypt: write columns of text[] in order[] sequence. */
static void columnar_enc_core(const uint8_t *text, size_t tlen,
                               int ncols, const int *order, FILE *out)
{
    if (tlen == 0) return;
    int nrows     = (int)((tlen + (size_t)ncols - 1) / (size_t)ncols);
    int full_cols = (int)(tlen % (size_t)ncols);
    for (int ci = 0; ci < ncols; ci++) {
        int col      = order[ci];
        int col_rows = COL_ROWS(col, nrows, full_cols);
        for (int r = 0; r < col_rows; r++)
            fputc((int)text[(size_t)r * (size_t)ncols + (size_t)col], out);
    }
}

/* Columnar decrypt: reconstruct plaintext from cipher and column order.
 * Returns malloc'd buffer of exactly clen bytes; caller must free(). */
static uint8_t *columnar_dec_core(const uint8_t *cipher, size_t clen,
                                   int ncols, const int *order)
{
    if (clen == 0) return (uint8_t *)calloc(1, 1);
    int nrows     = (int)((clen + (size_t)ncols - 1) / (size_t)ncols);
    int full_cols = (int)(clen % (size_t)ncols);

    /* Allocate the plain grid (row-major). */
    uint8_t *grid = (uint8_t *)calloc((size_t)(nrows * ncols), 1);
    if (!grid) die("out of memory");

    /* Fill each column from the cipher stream in sorted order. */
    size_t src = 0;
    for (int ci = 0; ci < ncols; ci++) {
        int col      = order[ci];
        int col_rows = COL_ROWS(col, nrows, full_cols);
        for (int r = 0; r < col_rows; r++)
            grid[(size_t)r * (size_t)ncols + (size_t)col] = cipher[src++];
    }

    /* Read the grid back in row-major order, skipping padding cells.
     * A cell (r, col) is padding iff r == nrows-1 AND col >= full_cols
     * (and full_cols != 0).  We collect exactly clen bytes. */
    uint8_t *result = (uint8_t *)malloc(clen);
    if (!result) { free(grid); die("out of memory"); }
    size_t dst = 0;
    for (int r = 0; r < nrows && dst < clen; r++)
        for (int c = 0; c < ncols && dst < clen; c++) {
            int is_pad = (full_cols != 0)
                         && (r == nrows - 1)
                         && (c >= full_cols);
            if (!is_pad)
                result[dst++] = grid[(size_t)r * (size_t)ncols + (size_t)c];
        }
    free(grid);
    return result;
}

/* ───────────────────────────────────────────────────────────────────────────
   SCYTALE  (~700 BC, Sparta)
   The oldest known device-based cipher. A leather strip was wound helically
   around a staff (skytale); the message was written lengthwise and appeared
   random when unwound. Only a staff of the same diameter could decode it.
   Here the key is the number of columns (the staff circumference in chars).
   ─────────────────────────────────────────────────────────────────────────── */
static void scytale_encrypt(FILE *in, FILE *out, int cols)
{
    if (cols < 2) die("Scytale: key must be an integer >= 2.");
    size_t tlen; uint8_t *text = read_all(in, &tlen);
    /* Identity order: read columns left-to-right */
    int *order = (int *)malloc((size_t)cols * sizeof(int));
    if (!order) die("out of memory");
    for (int i = 0; i < cols; i++) order[i] = i;
    columnar_enc_core(text, tlen, cols, order, out);
    free(text); free(order);
}

static void scytale_decrypt(FILE *in, FILE *out, int cols)
{
    if (cols < 2) die("Scytale: key must be an integer >= 2.");
    size_t clen; uint8_t *cipher = read_all(in, &clen);
    int *order = (int *)malloc((size_t)cols * sizeof(int));
    if (!order) die("out of memory");
    for (int i = 0; i < cols; i++) order[i] = i;
    uint8_t *plain = columnar_dec_core(cipher, clen, cols, order);
    fwrite(plain, 1, clen, out);
    free(cipher); free(order); free(plain);
}

/* ───────────────────────────────────────────────────────────────────────────
   AFFINE CIPHER  (classical antiquity)
   Generalisation of Caesar using modular arithmetic:
     encrypt: C = (a * P + b) mod 26
     decrypt: P = a_inv * (C - b) mod 26
   a must be coprime to 26: valid values are 1 3 5 7 9 11 15 17 19 21 23 25.
   Key format: "a,b"  (e.g. -k "7,3")
   Only letters are transformed; all other bytes pass through unchanged.
   ─────────────────────────────────────────────────────────────────────────── */
static int affine_modinv(int a, int m)
{
    int t = 0, newt = 1, r = m, newr = a;
    while (newr) {
        int q = r / newr, tmp;
        tmp = t - q * newt; t = newt; newt = tmp;
        tmp = r - q * newr; r = newr; newr = tmp;
    }
    return (r > 1) ? -1 : (t < 0 ? t + m : t);
}

static void affine_cipher(FILE *in, FILE *out, const char *key, int dec)
{
    int a = 1, b = 0;
    if (sscanf(key, "%d,%d", &a, &b) != 2)
        die("Affine: key must be \"a,b\" e.g. -k \"7,3\".");
    a = ((a % 26) + 26) % 26;
    b = ((b % 26) + 26) % 26;
    int a_inv = affine_modinv(a, 26);
    if (a_inv < 0)
        die("Affine: 'a' must be coprime to 26.\n"
            "       Valid values: 1 3 5 7 9 11 15 17 19 21 23 25");
    uint8_t buf[CHUNK_SIZE]; size_t n, i;
    while ((n = fread(buf, 1, CHUNK_SIZE, in)) > 0) {
        for (i = 0; i < n; i++) {
            uint8_t c = buf[i];
            if (isalpha(c)) {
                uint8_t base = isupper(c) ? 'A' : 'a';
                int p = c - base;
                int q = dec ? (a_inv * (p - b + 26)) % 26
                            : (a * p + b) % 26;
                buf[i] = (uint8_t)(base + q);
            }
        }
        fwrite(buf, 1, n, out);
    }
}

/* ───────────────────────────────────────────────────────────────────────────
   TRITHEMIUS CIPHER  (Johannes Trithemius, 1508)
   Described in Polygraphia (1508), the first printed book on cryptography.
   Each letter at position i (counting only letters) is shifted by i mod 26,
   using the tabula recta — an auto-key progressive Caesar. No secret keyword;
   it introduced the concept of a polyalphabetic cipher for later work.
   Only letters are transformed; other bytes pass through unchanged.
   ─────────────────────────────────────────────────────────────────────────── */
static void trithemius_cipher(FILE *in, FILE *out, int dec)
{
    uint8_t buf[CHUNK_SIZE]; size_t n, i;
    int shift = 0;
    while ((n = fread(buf, 1, CHUNK_SIZE, in)) > 0) {
        for (i = 0; i < n; i++) {
            uint8_t c = buf[i];
            if (isalpha(c)) {
                uint8_t base = isupper(c) ? 'A' : 'a';
                int p = c - base;
                int q = dec ? ((p - shift) % 26 + 26) % 26
                            : (p + shift) % 26;
                buf[i] = (uint8_t)(base + q);
                shift   = (shift + 1) % 26;
            }
        }
        fwrite(buf, 1, n, out);
    }
}

/* ───────────────────────────────────────────────────────────────────────────
   PORTA CIPHER  (Giovanni Battista della Porta, 1563)
   Described in De Furtivis Literarum Notis, the first book dedicated entirely
   to cryptanalysis. A 13-row reciprocal table keyed by a repeating keyword:
   each key-char selects a row; the row maps A–M <-> N–Z. Because the mapping
   is its own inverse, Porta is self-inverse.
   Only letters are transformed; other bytes pass through unchanged.
   ─────────────────────────────────────────────────────────────────────────── */
static const int PORTA_TABLE[13][13] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12},
    { 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12, 0},
    { 2, 3, 4, 5, 6, 7, 8, 9,10,11,12, 0, 1},
    { 3, 4, 5, 6, 7, 8, 9,10,11,12, 0, 1, 2},
    { 4, 5, 6, 7, 8, 9,10,11,12, 0, 1, 2, 3},
    { 5, 6, 7, 8, 9,10,11,12, 0, 1, 2, 3, 4},
    { 6, 7, 8, 9,10,11,12, 0, 1, 2, 3, 4, 5},
    { 7, 8, 9,10,11,12, 0, 1, 2, 3, 4, 5, 6},
    { 8, 9,10,11,12, 0, 1, 2, 3, 4, 5, 6, 7},
    { 9,10,11,12, 0, 1, 2, 3, 4, 5, 6, 7, 8},
    {10,11,12, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
    {11,12, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10},
    {12, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11},
};

static void porta_cipher(FILE *in, FILE *out, const char *key)
{
    size_t klen = strlen(key);
    if (!klen) die("Porta: key must be a non-empty alphabetic string.");
    for (size_t i = 0; i < klen; i++)
        if (!isalpha((unsigned char)key[i]))
            die("Porta: key must contain only letters (a-z / A-Z).");
    uint8_t buf[CHUNK_SIZE]; size_t n, ki = 0;
    while ((n = fread(buf, 1, CHUNK_SIZE, in)) > 0) {
        for (size_t i = 0; i < n; i++) {
            uint8_t c = buf[i];
            if (!isalpha(c)) continue;
            int upper = toupper(c) - 'A';
            int row   = (tolower(key[ki++ % klen]) - 'a') / 2;
            if (upper < 13) {
                buf[i] = (uint8_t)((isupper(c) ? 'N' : 'n')
                                   + PORTA_TABLE[row][upper]);
            } else {
                int target = upper - 13;
                for (int j = 0; j < 13; j++) {
                    if (PORTA_TABLE[row][j] == target) {
                        buf[i] = (uint8_t)((isupper(c) ? 'A' : 'a') + j);
                        break;
                    }
                }
            }
        }
        fwrite(buf, 1, n, out);
    }
}

/* ───────────────────────────────────────────────────────────────────────────
   BEAUFORT CIPHER  (Admiral Sir Francis Beaufort, 1857)
   Vigenère variant with the formula reversed: C = (K - P) mod 26.
   This makes it self-inverse: the same key and same operation both encrypts
   and decrypts. Used by the British Royal Navy; referenced in Ian Fleming's
   James Bond novels (From Russia with Love).
   Only letters are transformed; other bytes pass through unchanged.
   ─────────────────────────────────────────────────────────────────────────── */
static void beaufort_cipher(FILE *in, FILE *out, const char *key)
{
    size_t klen = strlen(key);
    if (!klen) die("Beaufort: key must be a non-empty alphabetic string.");
    for (size_t i = 0; i < klen; i++)
        if (!isalpha((unsigned char)key[i]))
            die("Beaufort: key must contain only letters (a-z / A-Z).");
    uint8_t buf[CHUNK_SIZE]; size_t n, ki = 0;
    while ((n = fread(buf, 1, CHUNK_SIZE, in)) > 0) {
        for (size_t i = 0; i < n; i++) {
            uint8_t c = buf[i];
            if (isalpha(c)) {
                uint8_t base = isupper(c) ? 'A' : 'a';
                int p = c - base;
                int k = tolower(key[ki++ % klen]) - 'a';
                buf[i] = (uint8_t)(base + ((k - p + 26) % 26));
            }
        }
        fwrite(buf, 1, n, out);
    }
}

/* ───────────────────────────────────────────────────────────────────────────
   ROT47  (Usenet, ~1990s)
   Extends ROT13 to all 94 printable ASCII characters (0x21 '!' to 0x7E '~').
   Each character is rotated 47 positions within that range, making the cipher
   self-inverse. Used on Usenet to hide spoilers and adult content.
   Characters outside 0x21–0x7E pass through unchanged.
   ─────────────────────────────────────────────────────────────────────────── */
static void rot47_cipher(FILE *in, FILE *out)
{
    uint8_t buf[CHUNK_SIZE]; size_t n, i;
    while ((n = fread(buf, 1, CHUNK_SIZE, in)) > 0) {
        for (i = 0; i < n; i++) {
            uint8_t c = buf[i];
            if (c >= 33 && c <= 126)
                buf[i] = (uint8_t)(33 + (c - 33 + 47) % 94);
        }
        fwrite(buf, 1, n, out);
    }
}

/* ───────────────────────────────────────────────────────────────────────────
   FOUR-SQUARE CIPHER  (Félix Delastelle, 1901)
   Invented by Félix Delastelle (who also devised bifid and trifid). Uses four
   5×5 Playfair-like squares: top-left and bottom-right are the standard plain
   alphabet (I=J); top-right is keyed from KEY1; bottom-left from KEY2.
   Encrypts digraphs: for (P1, P2), locate P1 in top-left and P2 in
   bottom-right; output is top-right[row(P1)][col(P2)] and
   bottom-left[row(P2)][col(P1)].
   Handles alpha only; J treated as I. Key format: "KEY1:KEY2".
   ─────────────────────────────────────────────────────────────────────────── */
static void foursquare_build(const char *key, char sq[5][5])
{
    int used[26] = {0}, r = 0, c = 0;
    for (int i = 0; key[i] && r < 5; i++) {
        int k = toupper((unsigned char)key[i]) - 'A';
        if (k < 0 || k > 25 || k == 9 || used[k]) continue; /* skip J */
        used[k] = 1; sq[r][c] = (char)('A' + k);
        if (++c == 5) { c = 0; r++; }
    }
    for (int k = 0; k < 26 && r < 5; k++) {
        if (k == 9 || used[k]) continue;
        sq[r][c] = (char)('A' + k);
        if (++c == 5) { c = 0; r++; }
    }
}

static const char FS_PLAIN[5][5] = {
    {'A','B','C','D','E'}, {'F','G','H','I','K'},
    {'L','M','N','O','P'}, {'Q','R','S','T','U'}, {'V','W','X','Y','Z'}
};

static void foursquare_find(const char sq[5][5], char c, int *row, int *col)
{
    for (int r = 0; r < 5; r++)
        for (int cc = 0; cc < 5; cc++)
            if (sq[r][cc] == c) { *row = r; *col = cc; return; }
}

static void foursquare_cipher(FILE *in, FILE *out, const char *key, int dec)
{
    char k1[256] = {0}, k2[256] = {0};
    const char *colon = strchr(key, ':');
    if (!colon) die("Four-Square: key must be \"KEY1:KEY2\".");
    size_t k1len = (size_t)(colon - key);
    if (k1len >= 256) die("Four-Square: KEY1 too long.");
    memcpy(k1, key, k1len);
    strncpy(k2, colon + 1, 255);

    char sq1[5][5], sq2[5][5];
    foursquare_build(k1, sq1);
    foursquare_build(k2, sq2);

    size_t tlen; uint8_t *text = read_all(in, &tlen);
    uint8_t *alpha = (uint8_t *)malloc(tlen + 2);
    if (!alpha) { free(text); die("Four-Square: out of memory."); }
    size_t alen = 0;
    for (size_t i = 0; i < tlen; i++) {
        int c = toupper(text[i]);
        if (c == 'J') c = 'I';
        if (c >= 'A' && c <= 'Z') alpha[alen++] = (uint8_t)c;
    }
    free(text);
    if (alen % 2 != 0) alpha[alen++] = 'X';

    for (size_t i = 0; i + 1 < alen; i += 2) {
        char p1 = (char)alpha[i], p2 = (char)alpha[i+1];
        int r1, c1, r2, c2;
        if (!dec) {
            foursquare_find(FS_PLAIN, p1, &r1, &c1);
            foursquare_find(FS_PLAIN, p2, &r2, &c2);
            fputc(sq1[r1][c2], out);
            fputc(sq2[r2][c1], out);
        } else {
            foursquare_find(sq1, p1, &r1, &c1);
            foursquare_find(sq2, p2, &r2, &c2);
            fputc(FS_PLAIN[r1][c2], out);
            fputc(FS_PLAIN[r2][c1], out);
        }
    }
    fputc('\n', out);
    free(alpha);
}

/* ───────────────────────────────────────────────────────────────────────────
   COLUMNAR TRANSPOSITION  (WWI / WWII field cipher)
   Used independently by France, Britain, and Germany in both World Wars.
   Plaintext is written row-by-row into a grid of ncols columns; columns are
   then read in the alphabetical order of keyword letters.
   Key: any alphabetic keyword (e.g. -k "ZEBRAS"). All bytes preserved.
   ─────────────────────────────────────────────────────────────────────────── */
static void columnar_encrypt(FILE *in, FILE *out, const char *key)
{
    int ncols = (int)strlen(key);
    if (ncols < 2) die("Columnar: key must be at least 2 characters.");
    size_t tlen; uint8_t *text = read_all(in, &tlen);
    int *order = keyword_order(key, ncols);
    columnar_enc_core(text, tlen, ncols, order, out);
    free(text); free(order);
}

static void columnar_decrypt(FILE *in, FILE *out, const char *key)
{
    int ncols = (int)strlen(key);
    if (ncols < 2) die("Columnar: key must be at least 2 characters.");
    size_t clen; uint8_t *cipher = read_all(in, &clen);
    int *order = keyword_order(key, ncols);
    uint8_t *plain = columnar_dec_core(cipher, clen, ncols, order);
    fwrite(plain, 1, clen, out);
    free(cipher); free(order); free(plain);
}

/* ───────────────────────────────────────────────────────────────────────────
   DOUBLE TRANSPOSITION  (SOE / Allied WWII field cipher)
   Two independent rounds of columnar transposition with separate keywords.
   Taught by the British SOE to resistance fighters in occupied Europe.
   Field agents memorised two keywords; the cipher was considered unbreakable
   without machine assistance.
   Key format: "KEY1:KEY2"  (e.g. -k "SECURITY:LONDON")
   ─────────────────────────────────────────────────────────────────────────── */
static void double_encrypt(FILE *in, FILE *out, const char *key)
{
    char k1[256] = {0}, k2[256] = {0};
    const char *colon = strchr(key, ':');
    if (!colon) die("Double transposition: key must be \"KEY1:KEY2\".");
    size_t k1len = (size_t)(colon - key);
    if (k1len < 1 || k1len >= 256) die("Double transposition: KEY1 invalid.");
    memcpy(k1, key, k1len);
    strncpy(k2, colon + 1, 255);
    if (!k2[0]) die("Double transposition: KEY2 cannot be empty.");

    int nc1 = (int)strlen(k1), nc2 = (int)strlen(k2);

    /* Round 1: plain -> intermediate buffer */
    size_t tlen; uint8_t *text = read_all(in, &tlen);
    int *ord1 = keyword_order(k1, nc1);
    uint8_t *mid = (uint8_t *)malloc(tlen ? tlen : 1);
    if (!mid) { free(text); free(ord1); die("out of memory"); }
    {
        int nrows1    = (int)((tlen + (size_t)nc1 - 1) / (size_t)nc1);
        int full1     = (int)(tlen % (size_t)nc1);
        size_t mlen   = 0;
        for (int ci = 0; ci < nc1; ci++) {
            int col      = ord1[ci];
            int col_rows = COL_ROWS(col, nrows1, full1);
            for (int r = 0; r < col_rows; r++)
                mid[mlen++] = text[(size_t)r * (size_t)nc1 + (size_t)col];
        }
    }
    free(text); free(ord1);

    /* Round 2: intermediate -> output */
    int *ord2 = keyword_order(k2, nc2);
    columnar_enc_core(mid, tlen, nc2, ord2, out);
    free(mid); free(ord2);
}

static void double_decrypt(FILE *in, FILE *out, const char *key)
{
    char k1[256] = {0}, k2[256] = {0};
    const char *colon = strchr(key, ':');
    if (!colon) die("Double transposition: key must be \"KEY1:KEY2\".");
    size_t k1len = (size_t)(colon - key);
    if (k1len < 1 || k1len >= 256) die("Double transposition: KEY1 invalid.");
    memcpy(k1, key, k1len);
    strncpy(k2, colon + 1, 255);

    int nc1 = (int)strlen(k1), nc2 = (int)strlen(k2);

    size_t clen; uint8_t *cipher = read_all(in, &clen);

    /* Reverse round 2 */
    int *ord2 = keyword_order(k2, nc2);
    uint8_t *mid = columnar_dec_core(cipher, clen, nc2, ord2);
    free(cipher); free(ord2);

    /* Reverse round 1 */
    int *ord1 = keyword_order(k1, nc1);
    uint8_t *plain = columnar_dec_core(mid, clen, nc1, ord1);
    fwrite(plain, 1, clen, out);
    free(mid); free(ord1); free(plain);
}

/* ───────────────────────────────────────────────────────────────────────────
   ATBASH  (~600 BC)
   Reverses the alphabet. A<->Z, B<->Y. Self-inverse.
   ─────────────────────────────────────────────────────────────────────────── */
static void atbash_cipher(FILE *in, FILE *out)
{
    uint8_t buf[CHUNK_SIZE]; size_t n, i;
    while ((n = fread(buf, 1, CHUNK_SIZE, in)) > 0) {
        for (i = 0; i < n; i++) {
            uint8_t c = buf[i];
            if      (c >= 'A' && c <= 'Z') buf[i] = (uint8_t)('Z' - (c - 'A'));
            else if (c >= 'a' && c <= 'z') buf[i] = (uint8_t)('z' - (c - 'a'));
        }
        fwrite(buf, 1, n, out);
    }
}

/* ───────────────────────────────────────────────────────────────────────────
   POLYBIUS SQUARE  (~200 BC)
   Standard 5x5 grid, I=J. Encode: letter -> "RC" (row-col digits 1-5).
   Decode: pairs of digits -> letter.
   Output is text (pairs separated by spaces).
   ─────────────────────────────────────────────────────────────────────────── */
static const char POLYBE_GRID[5][5] = {
    {'A','B','C','D','E'},
    {'F','G','H','I','K'},
    {'L','M','N','O','P'},
    {'Q','R','S','T','U'},
    {'V','W','X','Y','Z'}
};

static void polybe_encode(FILE *in, FILE *out)
{
    uint8_t buf[CHUNK_SIZE]; size_t n, i;
    int first = 1;
    while ((n = fread(buf, 1, CHUNK_SIZE, in)) > 0) {
        for (i = 0; i < n; i++) {
            uint8_t c = (uint8_t)toupper(buf[i]);
            if (c == 'J') c = 'I';
            if (c < 'A' || c > 'Z') continue;
            for (int r = 0; r < 5; r++)
                for (int col = 0; col < 5; col++)
                    if (POLYBE_GRID[r][col] == (char)c) {
                        if (!first) fputc(' ', out);
                        fprintf(out, "%d%d", r+1, col+1);
                        first = 0;
                    }
        }
    }
    fputc('\n', out);
}

static void polybe_decode(FILE *in, FILE *out)
{
    /* Read all, collect digit pairs */
    int d1 = -1;
    int ch;
    while ((ch = fgetc(in)) != EOF) {
        if (ch < '1' || ch > '5') { d1 = -1; continue; }
        if (d1 < 0) { d1 = ch - '1'; continue; }
        int d2 = ch - '1';
        char letter = POLYBE_GRID[d1][d2];
        fputc(letter, out);
        d1 = -1;
    }
}

/* ───────────────────────────────────────────────────────────────────────────
   BACON'S CIPHER  (Francis Bacon, 1605)
   Each letter A-Z -> 5-bit binary -> represented as A(0)/B(1) string.
   Encode: text -> "AAAAA AAAAB AAABA ..." (5 A/B chars per letter).
   Decode: groups of 5 A/B chars -> letters.
   ─────────────────────────────────────────────────────────────────────────── */
static void bacon_encode(FILE *in, FILE *out)
{
    uint8_t buf[CHUNK_SIZE]; size_t n, i;
    int first = 1;
    while ((n = fread(buf, 1, CHUNK_SIZE, in)) > 0) {
        for (i = 0; i < n; i++) {
            uint8_t c = (uint8_t)toupper(buf[i]);
            if (c < 'A' || c > 'Z') continue;
            int val = c - 'A';  /* 0-25 */
            if (!first) fputc(' ', out);
            for (int b = 4; b >= 0; b--)
                fputc((val >> b) & 1 ? 'B' : 'A', out);
            first = 0;
        }
    }
    fputc('\n', out);
}

static void bacon_decode(FILE *in, FILE *out)
{
    int bits[5], count = 0, ch;
    while ((ch = fgetc(in)) != EOF) {
        ch = toupper(ch);
        if (ch != 'A' && ch != 'B') continue;
        bits[count++] = (ch == 'B') ? 1 : 0;
        if (count == 5) {
            int val = 0;
            for (int b = 0; b < 5; b++) val = (val << 1) | bits[b];
            if (val < 26) fputc('A' + val, out);
            count = 0;
        }
    }
}

/* ───────────────────────────────────────────────────────────────────────────
   PLAYFAIR CIPHER  (Charles Wheatstone, 1854)
   5x5 key square, I=J. Digraph substitution.
   Rules: same row -> shift right, same col -> shift down, else -> rectangle.
   Padding: X inserted between repeated pairs, and at end if odd length.
   ─────────────────────────────────────────────────────────────────────────── */
typedef struct { char sq[5][5]; int pos[26]; } PF_CTX;

static void playfair_build(const char *key, PF_CTX *ctx)
{
    int used[26] = {0};
    int r = 0, c = 0;
    /* Insert key letters */
    for (int i = 0; key[i]; i++) {
        int k = toupper((unsigned char)key[i]) - 'A';
        if (k < 0 || k > 25) continue;
        if (k == 9) k = 8; /* J->I */
        if (used[k]) continue;
        used[k] = 1;
        ctx->sq[r][c] = (char)('A' + k);
        ctx->pos[k] = r * 5 + c;
        if (++c == 5) { c = 0; r++; }
    }
    /* Fill remaining */
    for (int k = 0; k < 26; k++) {
        if (k == 9) continue; /* skip J */
        if (used[k]) continue;
        ctx->sq[r][c] = (char)('A' + k);
        ctx->pos[k] = r * 5 + c;
        if (++c == 5) { c = 0; r++; }
    }
}

static void playfair_pair(PF_CTX *ctx, char a, char b, int dec, char *oa, char *ob)
{
    int ai = ctx->pos[a - 'A'], bi = ctx->pos[b - 'A'];
    int ar = ai / 5, ac = ai % 5;
    int br = bi / 5, bc = bi % 5;
    int d = dec ? 4 : 1; /* shift direction: +1 enc, +4 (=-1 mod 5) dec */
    if (ar == br) { /* same row */
        *oa = ctx->sq[ar][(ac + d) % 5];
        *ob = ctx->sq[br][(bc + d) % 5];
    } else if (ac == bc) { /* same col */
        *oa = ctx->sq[(ar + d) % 5][ac];
        *ob = ctx->sq[(br + d) % 5][bc];
    } else { /* rectangle */
        *oa = ctx->sq[ar][bc];
        *ob = ctx->sq[br][ac];
    }
}

static void playfair_cipher(FILE *in, FILE *out, const char *key, int dec)
{
    PF_CTX ctx;
    playfair_build(key, &ctx);

    /* Read all alpha chars */
    uint8_t *text = NULL; size_t tlen = 0, tcap = 0;
    int ch;
    while ((ch = fgetc(in)) != EOF) {
        ch = toupper(ch);
        if (ch == 'J') ch = 'I';
        if (ch < 'A' || ch > 'Z') continue;
        if (tlen + 1 > tcap) {
            tcap = tcap ? tcap * 2 : 256;
            text = (uint8_t *)realloc(text, tcap);
            if (!text) die("Playfair: out of memory.");
        }
        text[tlen++] = (uint8_t)ch;
    }

    if (!dec) {
        /* Insert X between repeated pairs, pad to even length */
        uint8_t *prep = NULL; size_t plen = 0, pcap = 0;
        for (size_t i = 0; i < tlen; ) {
            if (plen + 2 > pcap) {
                pcap = pcap ? pcap * 2 : 256;
                prep = (uint8_t *)realloc(prep, pcap);
                if (!prep) die("Playfair: out of memory.");
            }
            prep[plen++] = text[i];
            if (i + 1 < tlen && text[i] == text[i+1]) {
                prep[plen++] = 'X';
                i++;
            } else if (i + 1 < tlen) {
                prep[plen++] = text[i+1];
                i += 2;
            } else {
                prep[plen++] = 'X';
                i++;
            }
        }
        free(text); text = prep; tlen = plen;
    }

    /* Process digraphs */
    for (size_t i = 0; i + 1 < tlen; i += 2) {
        char oa, ob;
        playfair_pair(&ctx, (char)text[i], (char)text[i+1], dec, &oa, &ob);
        fputc(oa, out);
        fputc(ob, out);
    }
    fputc('\n', out);
    free(text);
}

/* ───────────────────────────────────────────────────────────────────────────
   RAIL FENCE CIPHER  (US Civil War era)
   Zigzag transposition across N rails.
   ─────────────────────────────────────────────────────────────────────────── */
static void railfence_encrypt(FILE *in, FILE *out, int rails)
{
    if (rails < 2) die("Rail Fence: key must be an integer >= 2.");
    uint8_t *text = NULL; size_t tlen = 0, tcap = 0;
    int ch;
    while ((ch = fgetc(in)) != EOF) {
        if (tlen + 1 > tcap) {
            tcap = tcap ? tcap * 2 : 256;
            text = (uint8_t *)realloc(text, tcap);
            if (!text) die("Rail Fence: out of memory.");
        }
        text[tlen++] = (uint8_t)ch;
    }

    /* Assign each char to a rail */
    int *rail_of = (int *)malloc(tlen * sizeof(int));
    if (!rail_of) { free(text); die("Rail Fence: out of memory."); }
    int r = 0, dir = 1;
    for (size_t i = 0; i < tlen; i++) {
        rail_of[i] = r;
        if (r == 0) dir = 1;
        else if (r == rails - 1) dir = -1;
        r += dir;
    }
    /* Write rail by rail */
    for (int ri = 0; ri < rails; ri++)
        for (size_t i = 0; i < tlen; i++)
            if (rail_of[i] == ri) fputc(text[i], out);

    free(rail_of); free(text);
}

static void railfence_decrypt(FILE *in, FILE *out, int rails)
{
    if (rails < 2) die("Rail Fence: key must be an integer >= 2.");
    uint8_t *text = NULL; size_t tlen = 0, tcap = 0;
    int ch;
    while ((ch = fgetc(in)) != EOF) {
        if (tlen + 1 > tcap) {
            tcap = tcap ? tcap * 2 : 256;
            text = (uint8_t *)realloc(text, tcap);
            if (!text) die("Rail Fence: out of memory.");
        }
        text[tlen++] = (uint8_t)ch;
    }

    int *rail_of = (int *)malloc(tlen * sizeof(int));
    int *rail_len = (int *)calloc((size_t)rails, sizeof(int));
    if (!rail_of || !rail_len) { free(text); free(rail_of); die("Rail Fence: out of memory."); }

    int r = 0, dir = 1;
    for (size_t i = 0; i < tlen; i++) {
        rail_of[i] = r;
        rail_len[r]++;
        if (r == 0) dir = 1;
        else if (r == rails - 1) dir = -1;
        r += dir;
    }

    /* Reconstruct: map position in flat output back to original position */
    uint8_t *plain = (uint8_t *)malloc(tlen);
    if (!plain) { free(text); free(rail_of); free(rail_len); die("Rail Fence: out of memory."); }

    /* For each rail, record start offset in the ciphertext */
    int *start = (int *)calloc((size_t)rails, sizeof(int));
    if (!start) die("Rail Fence: out of memory.");
    for (int ri = 1; ri < rails; ri++) start[ri] = start[ri-1] + rail_len[ri-1];

    int *cur = (int *)malloc((size_t)rails * sizeof(int));
    if (!cur) die("Rail Fence: out of memory.");
    for (int ri = 0; ri < rails; ri++) cur[ri] = start[ri];

    for (size_t i = 0; i < tlen; i++)
        plain[i] = text[cur[rail_of[i]]++];

    fwrite(plain, 1, tlen, out);
    free(text); free(rail_of); free(rail_len); free(start); free(cur); free(plain);
}

/* ───────────────────────────────────────────────────────────────────────────
   ADFGVX CIPHER  (German Army, 1918)
   Step 1: 6x6 Polybius square over {A,D,F,G,V,X} and 36 chars (A-Z + 0-9).
   Step 2: Columnar transposition using a second keyword.
   ─────────────────────────────────────────────────────────────────────────── */
static const char ADFGVX_LETTERS[] = "ADFGVX";
/* Default grid (key "DEUTSCH" for demonstration; actual grid built from sub-key) */

static void adfgvx_build_grid(const char *subkey, char grid[36])
{
    /* grid is 36 chars: A-Z then 0-9, permuted by subkey */
    char alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int used[36] = {0};
    int pos = 0;
    /* Insert subkey characters first */
    for (int i = 0; subkey[i] && pos < 36; i++) {
        char c = (char)toupper((unsigned char)subkey[i]);
        int idx = -1;
        if (c >= 'A' && c <= 'Z') idx = c - 'A';
        else if (c >= '0' && c <= '9') idx = 26 + (c - '0');
        if (idx < 0 || used[idx]) continue;
        used[idx] = 1;
        grid[pos++] = alpha[idx];
    }
    /* Fill rest */
    for (int i = 0; i < 36 && pos < 36; i++)
        if (!used[i]) grid[pos++] = alpha[i];
}

static void adfgvx_encrypt(FILE *in, FILE *out, const char *key)
{
    /* Parse key: "SUBKEY:TRANSKEY" */
    char subkey[256] = {0}, transkey[256] = {0};
    const char *colon = strchr(key, ':');
    if (!colon) die("ADFGVX: key must be \"SUBKEY:TRANSKEY\".");
    size_t slen = (size_t)(colon - key);
    if (slen >= 256) die("ADFGVX: subkey too long.");
    memcpy(subkey, key, slen);
    strncpy(transkey, colon + 1, 255);
    if (!transkey[0]) die("ADFGVX: transposition key cannot be empty.");

    char grid[36];
    adfgvx_build_grid(subkey, grid);

    /* Step 1: substitute */
    uint8_t *step1 = NULL; size_t s1len = 0, s1cap = 0;
    int ch;
    while ((ch = fgetc(in)) != EOF) {
        char c = (char)toupper(ch);
        int idx = -1;
        if (c >= 'A' && c <= 'Z') {
            for (int i = 0; i < 36; i++) if (grid[i] == c) { idx = i; break; }
        } else if (c >= '0' && c <= '9') {
            for (int i = 0; i < 36; i++) if (grid[i] == c) { idx = i; break; }
        }
        if (idx < 0) continue;
        if (s1len + 2 > s1cap) {
            s1cap = s1cap ? s1cap * 2 : 256;
            step1 = (uint8_t *)realloc(step1, s1cap);
            if (!step1) die("ADFGVX: out of memory.");
        }
        step1[s1len++] = (uint8_t)ADFGVX_LETTERS[idx / 6];
        step1[s1len++] = (uint8_t)ADFGVX_LETTERS[idx % 6];
    }

    /* Step 2: columnar transposition */
    int ncols = (int)strlen(transkey);
    int nrows = (int)((s1len + (size_t)ncols - 1) / (size_t)ncols);
    /* Pad with X if needed */
    size_t padded = (size_t)(nrows * ncols);
    step1 = (uint8_t *)realloc(step1, padded + 1);
    if (!step1) die("ADFGVX: out of memory.");
    for (size_t i = s1len; i < padded; i++) step1[i] = 'X';

    /* Sort columns by transkey letter order */
    int *order = (int *)malloc((size_t)ncols * sizeof(int));
    if (!order) die("ADFGVX: out of memory.");
    for (int i = 0; i < ncols; i++) order[i] = i;
    /* Bubble sort by transkey[i] */
    for (int i = 0; i < ncols - 1; i++)
        for (int j = i + 1; j < ncols; j++)
            if (toupper((unsigned char)transkey[order[i]]) >
                toupper((unsigned char)transkey[order[j]])) {
                int tmp = order[i]; order[i] = order[j]; order[j] = tmp;
            }

    /* Write columns in sorted order */
    for (int ci = 0; ci < ncols; ci++) {
        int col = order[ci];
        for (int ri = 0; ri < nrows; ri++)
            fputc(step1[ri * ncols + col], out);
    }
    fputc('\n', out);
    free(step1); free(order);
}

static void adfgvx_decrypt(FILE *in, FILE *out, const char *key)
{
    char subkey[256] = {0}, transkey[256] = {0};
    const char *colon = strchr(key, ':');
    if (!colon) die("ADFGVX: key must be \"SUBKEY:TRANSKEY\".");
    size_t slen = (size_t)(colon - key);
    if (slen >= 256) die("ADFGVX: subkey too long.");
    memcpy(subkey, key, slen);
    strncpy(transkey, colon + 1, 255);

    char grid[36];
    adfgvx_build_grid(subkey, grid);

    /* Read ADFGVX chars */
    uint8_t *cipher = NULL; size_t clen = 0, ccap = 0;
    int ch;
    while ((ch = fgetc(in)) != EOF) {
        ch = toupper(ch);
        if (ch=='A'||ch=='D'||ch=='F'||ch=='G'||ch=='V'||ch=='X') {
            if (clen + 1 > ccap) {
                ccap = ccap ? ccap * 2 : 256;
                cipher = (uint8_t *)realloc(cipher, ccap);
                if (!cipher) die("ADFGVX: out of memory.");
            }
            cipher[clen++] = (uint8_t)ch;
        }
    }

    /* Reverse columnar transposition */
    int ncols = (int)strlen(transkey);
    int nrows = (int)(clen / (size_t)ncols);

    int *order = (int *)malloc((size_t)ncols * sizeof(int));
    if (!order) die("ADFGVX: out of memory.");
    for (int i = 0; i < ncols; i++) order[i] = i;
    for (int i = 0; i < ncols - 1; i++)
        for (int j = i + 1; j < ncols; j++)
            if (toupper((unsigned char)transkey[order[i]]) >
                toupper((unsigned char)transkey[order[j]])) {
                int tmp = order[i]; order[i] = order[j]; order[j] = tmp;
            }

    uint8_t *step1 = (uint8_t *)malloc(clen + 1);
    if (!step1) die("ADFGVX: out of memory.");

    /* Fill columns back */
    size_t src = 0;
    for (int ci = 0; ci < ncols; ci++) {
        int col = order[ci];
        for (int ri = 0; ri < nrows; ri++)
            step1[ri * ncols + col] = cipher[src++];
    }

    /* Reverse substitution */
    for (size_t i = 0; i + 1 < clen; i += 2) {
        int r6 = -1, c6 = -1;
        for (int x = 0; x < 6; x++) {
            if (ADFGVX_LETTERS[x] == (char)step1[i])   r6 = x;
            if (ADFGVX_LETTERS[x] == (char)step1[i+1]) c6 = x;
        }
        if (r6 < 0 || c6 < 0) continue;
        fputc(grid[r6 * 6 + c6], out);
    }
    fputc('\n', out);
    free(cipher); free(step1); free(order);
}

/* ───────────────────────────────────────────────────────────────────────────
   ENIGMA MACHINE  (Full simulation, 1923-1945)

   Rotors I-V (Wehrmacht), Reflector B.
   3 rotors, notch-based stepping (double-stepping included).
   Plugboard (Steckerbrett) up to 13 pairs.
   Self-inverse: encrypt == decrypt with same settings.
   Only A-Z processed; other bytes pass through unchanged.
   ─────────────────────────────────────────────────────────────────────────── */

/* Rotor wirings (forward, A=0) */
static const char *ROTOR_WIRING[5] = {
    "EKMFLGDQVZNTOWYHXUSPAIBRCJ", /* I   */
    "AJDKSIRUXBLHWTMCQGZNPYFVOE", /* II  */
    "BDFHJLCPRTXVZNYEIWGAKMUSQO", /* III */
    "ESOVPZJAYQUIRHXLNFTGKDCMWB", /* IV  */
    "VZBRGITYUPSDNHLXAWMJQOFECK"  /* V   */
};
/* Rotor notch positions (turnover) */
static const char ROTOR_NOTCH[5] = { 'Q', 'E', 'V', 'J', 'Z' };
/* Reflector B */
static const char *REFLECTOR_B = "YRUHQSLDPXNGOKMIEBFZCWVJAT";

typedef struct {
    int  rotor[3];    /* rotor indices 0-4 (I=0 .. V=4) */
    int  pos[3];      /* current positions 0-25 */
    int  ring[3];     /* ring settings 0-25 */
    int  plug[26];    /* plugboard: plug[i]=j means i<->j swap */
} ENIGMA;

static void enigma_parse_key(const char *key, ENIGMA *e)
{
    /* Format: "R1:R2:R3:POS:PAIRS"  e.g. "I:II:III:AAA:AB CD" */
    char buf[512];
    strncpy(buf, key, 511); buf[511] = '\0';

    /* Default identity plugboard */
    for (int i = 0; i < 26; i++) e->plug[i] = i;

    char *tok;
    char *rest = buf;

    /* R1 */
    tok = strsep(&rest, ":");
    if (!tok) die("Enigma: key format must be \"R1:R2:R3:POS:PAIRS\".");
    while (*tok == ' ') tok++;
    int rnum = atoi(tok);
    if (rnum < 1 || rnum > 5) {
        /* try Roman numeral */
        if      (!strncmp(tok,"I",1) && tok[1]=='\0') rnum=1;
        else if (!strncmp(tok,"II",2)&& tok[2]=='\0') rnum=2;
        else if (!strncmp(tok,"III",3)&&tok[3]=='\0') rnum=3;
        else if (!strncmp(tok,"IV",2)&& tok[2]=='\0') rnum=4;
        else if (!strncmp(tok,"V",1) && tok[1]=='\0') rnum=5;
        else die("Enigma: rotor must be I II III IV or V.");
    }
    e->rotor[0] = rnum - 1;

    /* R2 */
    tok = strsep(&rest, ":");
    if (!tok) die("Enigma: missing R2.");
    while (*tok == ' ') tok++;
    rnum = atoi(tok);
    if (rnum < 1 || rnum > 5) {
        if      (!strncmp(tok,"I",1)&&tok[1]=='\0') rnum=1;
        else if (!strncmp(tok,"II",2)&&tok[2]=='\0') rnum=2;
        else if (!strncmp(tok,"III",3)&&tok[3]=='\0') rnum=3;
        else if (!strncmp(tok,"IV",2)&&tok[2]=='\0') rnum=4;
        else if (!strncmp(tok,"V",1)&&tok[1]=='\0') rnum=5;
        else die("Enigma: rotor must be I II III IV or V.");
    }
    e->rotor[1] = rnum - 1;

    /* R3 */
    tok = strsep(&rest, ":");
    if (!tok) die("Enigma: missing R3.");
    while (*tok == ' ') tok++;
    rnum = atoi(tok);
    if (rnum < 1 || rnum > 5) {
        if      (!strncmp(tok,"I",1)&&tok[1]=='\0') rnum=1;
        else if (!strncmp(tok,"II",2)&&tok[2]=='\0') rnum=2;
        else if (!strncmp(tok,"III",3)&&tok[3]=='\0') rnum=3;
        else if (!strncmp(tok,"IV",2)&&tok[2]=='\0') rnum=4;
        else if (!strncmp(tok,"V",1)&&tok[1]=='\0') rnum=5;
        else die("Enigma: rotor must be I II III IV or V.");
    }
    e->rotor[2] = rnum - 1;

    /* Position (3 letters) */
    tok = strsep(&rest, ":");
    if (!tok || strlen(tok) < 3) die("Enigma: position must be 3 letters e.g. AAA.");
    for (int i = 0; i < 3; i++)
        e->pos[i] = toupper((unsigned char)tok[i]) - 'A';

    /* Ring settings default AAA */
    for (int i = 0; i < 3; i++) e->ring[i] = 0;

    /* Plugboard pairs (rest of string) */
    if (rest) {
        /* pairs separated by spaces e.g. "AB CD EF" */
        char *p = rest;
        while (*p) {
            while (*p == ' ') p++;
            if (!*p) break;
            char a = (char)toupper((unsigned char)*p++);
            char b = (char)toupper((unsigned char)*p++);
            if (a < 'A' || a > 'Z' || b < 'A' || b > 'Z') break;
            e->plug[a - 'A'] = b - 'A';
            e->plug[b - 'A'] = a - 'A';
        }
    }
}

/* Build inverse wiring table for backward pass through a rotor */
static void enigma_inverse(const char *fwd, int inv[26])
{
    for (int i = 0; i < 26; i++)
        inv[fwd[i] - 'A'] = i;
}

static int enigma_encrypt_char(ENIGMA *e, int c)
{
    /* Step rotors (right to left: e->rotor[2] is rightmost) */
    /* Double-stepping anomaly included */
    int r0 = e->rotor[0], r1 = e->rotor[1], r2 = e->rotor[2];
    int notch1 = (ROTOR_NOTCH[r1] - 'A');
    int notch2 = (ROTOR_NOTCH[r2] - 'A');

    int step_mid   = (e->pos[1] == notch1); /* middle at notch -> all three step */
    int step_right = 1;                      /* right always steps */
    int step_left  = step_mid;               /* left steps when middle steps */

    /* Double-step: middle steps again if right is at notch */
    if (e->pos[2] == notch2) step_mid = 1;

    if (step_right) e->pos[2] = (e->pos[2] + 1) % 26;
    if (step_mid)   e->pos[1] = (e->pos[1] + 1) % 26;
    if (step_left)  e->pos[0] = (e->pos[0] + 1) % 26;

    /* Plugboard in */
    c = e->plug[c];

    /* Right rotor forward */
    c = (ROTOR_WIRING[r2][(c + e->pos[2] - e->ring[2] + 26) % 26] - 'A'
         - e->pos[2] + e->ring[2] + 52) % 26;
    /* Middle rotor forward */
    c = (ROTOR_WIRING[r1][(c + e->pos[1] - e->ring[1] + 26) % 26] - 'A'
         - e->pos[1] + e->ring[1] + 52) % 26;
    /* Left rotor forward */
    c = (ROTOR_WIRING[r0][(c + e->pos[0] - e->ring[0] + 26) % 26] - 'A'
         - e->pos[0] + e->ring[0] + 52) % 26;

    /* Reflector B */
    c = REFLECTOR_B[c] - 'A';

    /* Left rotor backward */
    int inv0[26]; enigma_inverse(ROTOR_WIRING[r0], inv0);
    c = (inv0[(c + e->pos[0] - e->ring[0] + 26) % 26]
         - e->pos[0] + e->ring[0] + 52) % 26;
    /* Middle rotor backward */
    int inv1[26]; enigma_inverse(ROTOR_WIRING[r1], inv1);
    c = (inv1[(c + e->pos[1] - e->ring[1] + 26) % 26]
         - e->pos[1] + e->ring[1] + 52) % 26;
    /* Right rotor backward */
    int inv2[26]; enigma_inverse(ROTOR_WIRING[r2], inv2);
    c = (inv2[(c + e->pos[2] - e->ring[2] + 26) % 26]
         - e->pos[2] + e->ring[2] + 52) % 26;

    /* Plugboard out */
    c = e->plug[c];
    return c;
}

static void enigma_cipher(FILE *in, FILE *out, const char *key)
{
    ENIGMA e;
    enigma_parse_key(key, &e);

    int ch;
    while ((ch = fgetc(in)) != EOF) {
        int upper = toupper(ch);
        if (upper >= 'A' && upper <= 'Z') {
            int enc = enigma_encrypt_char(&e, upper - 'A');
            /* Preserve original case */
            fputc(isupper(ch) ? 'A' + enc : 'a' + enc, out);
        } else {
            fputc(ch, out); /* non-alpha passes through */
        }
    }
}

/* ───────────────────────────────────────────────────────────────────────────
   VERNAM / ONE-TIME PAD  (Gilbert Vernam, 1917)
   Key is a FILE (same size as input), specified as @/path/to/file.
   XOR with the key stream. Provably secure when key is truly random and
   never reused (Shannon, 1949).
   ─────────────────────────────────────────────────────────────────────────── */
static void vernam_cipher(FILE *in, FILE *out, const char *keyspec)
{
    if (keyspec[0] != '@')
        die("Vernam: key must be a file path prefixed with '@'  (e.g. -k \"@/path/key.bin\").");
    const char *kpath = keyspec + 1;
    FILE *kf = fopen(kpath, "rb");
    if (!kf) { perror(kpath); exit(EXIT_FAILURE); }

    uint8_t ibuf[CHUNK_SIZE], kbuf[CHUNK_SIZE];
    size_t n, kn;
    while ((n = fread(ibuf, 1, CHUNK_SIZE, in)) > 0) {
        kn = fread(kbuf, 1, n, kf);
        if (kn < n) {
            fclose(kf);
            die("Vernam: key file is shorter than input file.\n"
                "       Key must be at least as large as the input.");
        }
        for (size_t i = 0; i < n; i++) ibuf[i] ^= kbuf[i];
        fwrite(ibuf, 1, n, out);
    }
    fclose(kf);
}

/* ═══════════════════════════════════════════════════════════════════════════
   ███  PURE-C MODERN STREAM CIPHERS
   ═══════════════════════════════════════════════════════════════════════════ */

static void xor_cipher(FILE *in, FILE *out, const char *key)
{
    size_t klen = strlen(key);
    if (!klen) die("XOR requires a non-empty key.");
    uint8_t buf[CHUNK_SIZE]; size_t n, i, ki = 0;
    while ((n = fread(buf, 1, CHUNK_SIZE, in)) > 0) {
        for (i = 0; i < n; i++) buf[i] ^= (uint8_t)key[ki++ % klen];
        fwrite(buf, 1, n, out);
    }
}

static void rot13_cipher(FILE *in, FILE *out)
{
    uint8_t buf[CHUNK_SIZE]; size_t n, i;
    while ((n = fread(buf, 1, CHUNK_SIZE, in)) > 0) {
        for (i = 0; i < n; i++) {
            uint8_t c = buf[i];
            if      (c >= 'A' && c <= 'Z') buf[i] = (uint8_t)((c-'A'+13)%26+'A');
            else if (c >= 'a' && c <= 'z') buf[i] = (uint8_t)((c-'a'+13)%26+'a');
        }
        fwrite(buf, 1, n, out);
    }
}

static void caesar_encrypt(FILE *in, FILE *out, int sh)
{
    sh = ((sh % 256) + 256) % 256;
    uint8_t buf[CHUNK_SIZE]; size_t n, i;
    while ((n = fread(buf, 1, CHUNK_SIZE, in)) > 0) {
        for (i = 0; i < n; i++) buf[i] = (uint8_t)((buf[i] + sh) & 0xFF);
        fwrite(buf, 1, n, out);
    }
}
static void caesar_decrypt(FILE *in, FILE *out, int sh) { caesar_encrypt(in, out, -sh); }

typedef struct { uint8_t S[256]; uint8_t i, j; } RC4_CTX;
static void rc4_init(RC4_CTX *c, const uint8_t *k, size_t kl)
{
    int i, j = 0;
    for (i = 0; i < 256; i++) c->S[i] = (uint8_t)i;
    for (i = 0; i < 256; i++) {
        j = (j + c->S[i] + k[i%kl]) & 0xFF;
        uint8_t t = c->S[i]; c->S[i] = c->S[j]; c->S[j] = t;
    }
    c->i = c->j = 0;
}
static uint8_t rc4_byte(RC4_CTX *c)
{
    c->i=(c->i+1)&0xFF; c->j=(c->j+c->S[c->i])&0xFF;
    uint8_t t=c->S[c->i]; c->S[c->i]=c->S[c->j]; c->S[c->j]=t;
    return c->S[(c->S[c->i]+c->S[c->j])&0xFF];
}
static void rc4_cipher(FILE *in, FILE *out, const char *key)
{
    size_t kl = strlen(key); if (!kl) die("RC4 requires a non-empty key.");
    RC4_CTX ctx; rc4_init(&ctx, (const uint8_t *)key, kl);
    uint8_t buf[CHUNK_SIZE]; size_t n, i;
    while ((n = fread(buf, 1, CHUNK_SIZE, in)) > 0) {
        for (i = 0; i < n; i++) buf[i] ^= rc4_byte(&ctx);
        fwrite(buf, 1, n, out);
    }
}

static void vigenere_cipher(FILE *in, FILE *out, const char *key, int dec)
{
    size_t kl = strlen(key); if (!kl) die("Vigenere requires a non-empty key.");
    for (size_t c = 0; c < kl; c++)
        if (!isalpha((unsigned char)key[c])) die("Vigenere key must contain only letters.");
    uint8_t buf[CHUNK_SIZE]; size_t n, i, ki = 0;
    while ((n = fread(buf, 1, CHUNK_SIZE, in)) > 0) {
        for (i = 0; i < n; i++) {
            uint8_t c = buf[i];
            if (isalpha(c)) {
                uint8_t base = isupper(c) ? 'A' : 'a';
                int sh = tolower(key[ki++ % kl]) - 'a';
                if (dec) sh = -sh;
                buf[i] = (uint8_t)(((c - base + sh + 26) % 26) + base);
            }
        }
        fwrite(buf, 1, n, out);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
   ███  OPENSSL HELPERS
   ═══════════════════════════════════════════════════════════════════════════ */

static void derive_key_iv(const char *pass, const uint8_t *salt,
                           const EVP_CIPHER *ciph, uint8_t *key, uint8_t *iv)
{
    int kl = EVP_CIPHER_key_length(ciph), il = EVP_CIPHER_iv_length(ciph);
    if (!PKCS5_PBKDF2_HMAC(pass,(int)strlen(pass),salt,SALT_LEN,KDF_ITER,EVP_sha256(),kl,key))
        openssl_die("PBKDF2 key");
    if (il > 0) {
        uint8_t ivsalt[SALT_LEN]; memcpy(ivsalt,salt,SALT_LEN); ivsalt[0]^=0xFF;
        if (!PKCS5_PBKDF2_HMAC(pass,(int)strlen(pass),ivsalt,SALT_LEN,KDF_ITER,EVP_sha256(),il,iv))
            openssl_die("PBKDF2 IV");
    }
}

/* CBC ─────────────────────────────────────────────────────────────────────── */
static void ossl_cbc_encrypt(FILE *in,FILE *out,const char *pass,const EVP_CIPHER *ciph)
{
    uint8_t salt[SALT_LEN];
    if (RAND_bytes(salt,SALT_LEN)!=1) openssl_die("RAND_bytes");
    fwrite(salt,1,SALT_LEN,out);
    uint8_t key[MAX_KEY_BYTES]={0}, iv[MAX_IV_BYTES]={0};
    derive_key_iv(pass,salt,ciph,key,iv);
    EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new(); if(!ctx) openssl_die("CTX_new");
    if(!EVP_EncryptInit_ex(ctx,ciph,NULL,key,iv)) openssl_die("EncryptInit");
    uint8_t ibuf[CHUNK_SIZE],obuf[CHUNK_SIZE+EVP_MAX_BLOCK_LENGTH];
    int ol; size_t n;
    while((n=fread(ibuf,1,CHUNK_SIZE,in))>0){
        if(!EVP_EncryptUpdate(ctx,obuf,&ol,ibuf,(int)n)) openssl_die("EncryptUpdate");
        fwrite(obuf,1,(size_t)ol,out);
    }
    if(!EVP_EncryptFinal_ex(ctx,obuf,&ol)) openssl_die("EncryptFinal");
    fwrite(obuf,1,(size_t)ol,out);
    EVP_CIPHER_CTX_free(ctx);
}

static void ossl_cbc_decrypt(FILE *in,FILE *out,const char *pass,const EVP_CIPHER *ciph)
{
    uint8_t salt[SALT_LEN];
    if(fread(salt,1,SALT_LEN,in)!=SALT_LEN) die("Input too short -- missing salt header.");
    uint8_t key[MAX_KEY_BYTES]={0}, iv[MAX_IV_BYTES]={0};
    derive_key_iv(pass,salt,ciph,key,iv);
    EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new(); if(!ctx) openssl_die("CTX_new");
    if(!EVP_DecryptInit_ex(ctx,ciph,NULL,key,iv)) openssl_die("DecryptInit");
    uint8_t ibuf[CHUNK_SIZE],obuf[CHUNK_SIZE+EVP_MAX_BLOCK_LENGTH];
    int ol; size_t n;
    while((n=fread(ibuf,1,CHUNK_SIZE,in))>0){
        if(!EVP_DecryptUpdate(ctx,obuf,&ol,ibuf,(int)n)) openssl_die("DecryptUpdate");
        fwrite(obuf,1,(size_t)ol,out);
    }
    if(!EVP_DecryptFinal_ex(ctx,obuf,&ol)){
        fprintf(stderr,"[ERROR] Decryption failed -- wrong key or corrupted file.\n");
        EVP_CIPHER_CTX_free(ctx); exit(EXIT_FAILURE);
    }
    fwrite(obuf,1,(size_t)ol,out);
    EVP_CIPHER_CTX_free(ctx);
}

/* AEAD (GCM / ChaCha20-Poly1305) ─────────────────────────────────────────── */
static void ossl_aead_encrypt(FILE *in,FILE *out,const char *pass,const EVP_CIPHER *ciph)
{
    uint8_t salt[SALT_LEN],nonce[GCM_IV_LEN];
    if(RAND_bytes(salt,SALT_LEN)!=1||RAND_bytes(nonce,GCM_IV_LEN)!=1) openssl_die("RAND_bytes");
    fwrite(salt,1,SALT_LEN,out); fwrite(nonce,1,GCM_IV_LEN,out);
    uint8_t key[MAX_KEY_BYTES]={0}, iv_unused[MAX_IV_BYTES]={0};
    derive_key_iv(pass,salt,ciph,key,iv_unused);
    EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new(); if(!ctx) openssl_die("CTX_new");
    if(!EVP_EncryptInit_ex(ctx,ciph,NULL,NULL,NULL)) openssl_die("AEAD Init1");
    if(!EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,GCM_IV_LEN,NULL)) openssl_die("AEAD IVlen");
    if(!EVP_EncryptInit_ex(ctx,NULL,NULL,key,nonce)) openssl_die("AEAD Init2");
    uint8_t ibuf[CHUNK_SIZE],obuf[CHUNK_SIZE+EVP_MAX_BLOCK_LENGTH];
    int ol; size_t n;
    while((n=fread(ibuf,1,CHUNK_SIZE,in))>0){
        if(!EVP_EncryptUpdate(ctx,obuf,&ol,ibuf,(int)n)) openssl_die("AEAD EncUpdate");
        fwrite(obuf,1,(size_t)ol,out);
    }
    if(!EVP_EncryptFinal_ex(ctx,obuf,&ol)) openssl_die("AEAD EncFinal");
    fwrite(obuf,1,(size_t)ol,out);
    uint8_t tag[GCM_TAG_LEN];
    if(!EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,GCM_TAG_LEN,tag)) openssl_die("AEAD GetTag");
    fwrite(tag,1,GCM_TAG_LEN,out);
    EVP_CIPHER_CTX_free(ctx);
}

static void ossl_aead_decrypt(FILE *in,FILE *out,const char *pass,const EVP_CIPHER *ciph)
{
    uint8_t salt[SALT_LEN],nonce[GCM_IV_LEN];
    if(fread(salt,1,SALT_LEN,in)!=SALT_LEN||fread(nonce,1,GCM_IV_LEN,in)!=GCM_IV_LEN)
        die("Input too short -- missing AEAD header.");
    uint8_t *cbuf=NULL; size_t clen=0,ccap=0;
    uint8_t tmp[CHUNK_SIZE]; size_t n;
    while((n=fread(tmp,1,CHUNK_SIZE,in))>0){
        if(clen+n>ccap){ccap=clen+n+CHUNK_SIZE;cbuf=(uint8_t*)realloc(cbuf,ccap);if(!cbuf)die("OOM");}
        memcpy(cbuf+clen,tmp,n); clen+=n;
    }
    if(clen<GCM_TAG_LEN){free(cbuf);die("Input too short -- no auth tag.");}
    size_t dlen=clen-GCM_TAG_LEN;
    uint8_t tag[GCM_TAG_LEN]; memcpy(tag,cbuf+dlen,GCM_TAG_LEN);
    uint8_t key[MAX_KEY_BYTES]={0},iv_unused[MAX_IV_BYTES]={0};
    derive_key_iv(pass,salt,ciph,key,iv_unused);
    EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new(); if(!ctx){free(cbuf);openssl_die("CTX_new");}
    if(!EVP_DecryptInit_ex(ctx,ciph,NULL,NULL,NULL)) openssl_die("AEAD DInit1");
    if(!EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,GCM_IV_LEN,NULL)) openssl_die("AEAD IVlen");
    if(!EVP_DecryptInit_ex(ctx,NULL,NULL,key,nonce)) openssl_die("AEAD DInit2");
    if(!EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_TAG,GCM_TAG_LEN,tag)) openssl_die("AEAD SetTag");
    uint8_t *obuf=(uint8_t*)malloc(dlen+EVP_MAX_BLOCK_LENGTH+1); if(!obuf){free(cbuf);die("OOM");}
    int ol=0,ol2=0;
    if(!EVP_DecryptUpdate(ctx,obuf,&ol,cbuf,(int)dlen)){free(cbuf);free(obuf);openssl_die("AEAD DUpdate");}
    free(cbuf);
    if(!EVP_DecryptFinal_ex(ctx,obuf+ol,&ol2)){
        free(obuf); EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr,"[ERROR] Authentication FAILED -- wrong key or tampered file.\n");
        exit(EXIT_FAILURE);
    }
    fwrite(obuf,1,(size_t)(ol+ol2),out);
    free(obuf); EVP_CIPHER_CTX_free(ctx);
}

/* ═══════════════════════════════════════════════════════════════════════════
   ███  HASH
   ═══════════════════════════════════════════════════════════════════════════ */

static void hash_file(FILE *in, const char *alg, const char *ipath, FILE *fout)
{
    const char *ossl;
    if      (!strcmp(alg,"md4"))      ossl="md4";
    else if (!strcmp(alg,"md5"))      ossl="md5";
    else if (!strcmp(alg,"sha"))      ossl="sha1";   /* "sha" = alias for sha1; SHA-0 unavailable */
    else if (!strcmp(alg,"sha1"))     ossl="sha1";
    else if (!strcmp(alg,"sha224"))   ossl="sha224";
    else if (!strcmp(alg,"sha256"))   ossl="sha256";
    else if (!strcmp(alg,"sha384"))   ossl="sha384";
    else if (!strcmp(alg,"sha512"))   ossl="sha512";
    else if (!strcmp(alg,"sha3-256")) ossl="sha3-256";
    else if (!strcmp(alg,"sha3-512")) ossl="sha3-512";
    else if (!strcmp(alg,"blake2b"))  ossl="blake2b512";
    else if (!strcmp(alg,"blake2s"))  ossl="blake2s256";
    else {
        fprintf(stderr,"[ERROR] Unknown hash \"%s\".\n"
                "        Supported: md4 md5 sha sha1 sha224 sha256 sha384 sha512\n"
                "                   sha3-256 sha3-512 blake2b blake2s\n",alg);
        exit(EXIT_FAILURE);
    }
    const EVP_MD *md=EVP_get_digestbyname(ossl);
    if(!md){fprintf(stderr,"[ERROR] \"%s\" not in this OpenSSL build.\n",ossl);exit(1);}
    EVP_MD_CTX *ctx=EVP_MD_CTX_new(); if(!ctx) openssl_die("MD_CTX_new");
    if(!EVP_DigestInit_ex(ctx,md,NULL)) openssl_die("DigestInit");
    uint8_t buf[CHUNK_SIZE]; size_t n;
    while((n=fread(buf,1,CHUNK_SIZE,in))>0)
        if(!EVP_DigestUpdate(ctx,buf,n)) openssl_die("DigestUpdate");
    uint8_t dig[EVP_MAX_MD_SIZE]; unsigned dl=0;
    if(!EVP_DigestFinal_ex(ctx,dig,&dl)) openssl_die("DigestFinal");
    EVP_MD_CTX_free(ctx);
    char hex[EVP_MAX_MD_SIZE*2+1];
    for(unsigned i=0;i<dl;i++) sprintf(hex+i*2,"%02x",dig[i]);
    hex[dl*2]='\0';
    printf("[%s]  %s  %s\n",alg,hex,ipath);
    if(fout){fprintf(fout,"%s  %s\n",hex,ipath);fflush(fout);}
}

/* ═══════════════════════════════════════════════════════════════════════════
   ███  OpenSSL cipher dispatch table
   ═══════════════════════════════════════════════════════════════════════════ */

typedef struct { const char *name; const char *ossl_name; int is_aead; } CipherEntry;

static const CipherEntry CIPHER_TABLE[] = {
    /* Legacy ciphers (require OpenSSL legacy provider — loaded automatically) */
    {"des",           "des-cbc",         0},
    {"blowfish",      "bf-cbc",          0},
    {"cast5",         "cast5-cbc",       0},
    {"3des",          "des-ede3-cbc",    0},
    /* International standards — CBC */
    {"camellia-128",  "camellia-128-cbc",0},
    {"camellia-256",  "camellia-256-cbc",0},
    {"aria-128",      "aria-128-cbc",    0},
    {"aria-256",      "aria-256-cbc",    0},
    {"sm4",           "sm4-cbc",         0},
    /* AES — CBC */
    {"aes-128",       "aes-128-cbc",     0},
    {"aes-192",       "aes-192-cbc",     0},
    {"aes-256",       "aes-256-cbc",     0},
    /* AES — GCM (authenticated) */
    {"aes-128-gcm",   "aes-128-gcm",     1},
    {"aes-192-gcm",   "aes-192-gcm",     1},
    {"aes-256-gcm",   "aes-256-gcm",     1},
    {NULL,NULL,0}
};

/* ═══════════════════════════════════════════════════════════════════════════
   ███  main
   ═══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[])
{
    const char *mode=NULL, *method=NULL, *key=NULL;
    const char *ipath=NULL, *opath=NULL;

    for(int a=1;a<argc;a++)
        if(!strcmp(argv[a],"-h")||!strcmp(argv[a],"--help"))
            {print_help(argv[0]);return 0;}

    for(int a=1;a<argc;a++){
        if     (!strcmp(argv[a],"-e")    &&a+1<argc){mode="e";   method=argv[++a];}
        else if(!strcmp(argv[a],"-d")    &&a+1<argc){mode="d";   method=argv[++a];}
        else if(!strcmp(argv[a],"--hash")&&a+1<argc){mode="hash";method=argv[++a];}
        else if(!strcmp(argv[a],"-k")    &&a+1<argc){key  =argv[++a];}
        else if(!strcmp(argv[a],"-i")    &&a+1<argc){ipath=argv[++a];}
        else if(!strcmp(argv[a],"-o")    &&a+1<argc){opath=argv[++a];}
        else fprintf(stderr,"[WARN] Unknown argument: %s\n",argv[a]);
    }

    if(!mode)  die("Missing mode. Use -e / -d / --hash.  Run -h for help.");
    if(!ipath) die("Missing -i <input>.  Run -h for help.");

    int is_hash=!strcmp(mode,"hash");
    int dec    =!strcmp(mode,"d");

    if(!is_hash && !key)   die("Missing -k <key>.  Run -h for help.");
    if(!is_hash && !opath) die("Missing -o <output>.  Run -h for help.");

    FILE *in=fopen(ipath,"rb");
    if(!in){perror(ipath);return 1;}
    FILE *out=NULL;
    if(opath){out=fopen(opath,is_hash?"w":"wb");if(!out){perror(opath);fclose(in);return 1;}}

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Load the OpenSSL legacy provider so that DES, Blowfish, CAST5, and MD4
     * are available.  The default provider is always loaded implicitly.
     * Failure is non-fatal: modern ciphers still work; only legacy ones will
     * report "not available in this OpenSSL build" if the module is missing. */
    OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER_load(NULL, "default");

    /* ── Hash ──────────────────────────────────────────────────────────── */
    if(is_hash){
        hash_file(in,method,ipath,out);
        fclose(in); if(out){fclose(out);printf("[OK] Digest saved to '%s'\n",opath);}
        return 0;
    }

    /* ── Historical ciphers ────────────────────────────────────────────── */
    if(!strcmp(method,"scytale")){
        char *ep; long cols=strtol(key,&ep,10);
        if(*ep||cols<2) die("Scytale: key must be an integer >= 2.");
        if(dec) scytale_decrypt(in,out,(int)cols);
        else    scytale_encrypt(in,out,(int)cols);
        goto done;
    }
    if(!strcmp(method,"affine")){
        affine_cipher(in,out,key,dec); goto done;
    }
    if(!strcmp(method,"trithemius")){
        trithemius_cipher(in,out,dec); goto done;
    }
    if(!strcmp(method,"porta")){
        porta_cipher(in,out,key); goto done; /* self-inverse */
    }
    if(!strcmp(method,"atbash")){
        atbash_cipher(in,out); goto done;
    }
    if(!strcmp(method,"polybe")){
        if(dec) polybe_decode(in,out); else polybe_encode(in,out); goto done;
    }
    if(!strcmp(method,"bacon")){
        if(dec) bacon_decode(in,out); else bacon_encode(in,out); goto done;
    }
    if(!strcmp(method,"beaufort")){
        beaufort_cipher(in,out,key); goto done; /* self-inverse */
    }
    if(!strcmp(method,"rot47")){
        rot47_cipher(in,out); goto done; /* self-inverse */
    }
    if(!strcmp(method,"playfair")){
        playfair_cipher(in,out,key,dec); goto done;
    }
    if(!strcmp(method,"foursquare")){
        foursquare_cipher(in,out,key,dec); goto done;
    }
    if(!strcmp(method,"railfence")){
        char *ep; long rails=strtol(key,&ep,10);
        if(*ep||rails<2) die("Rail Fence: key must be an integer >= 2.");
        if(dec) railfence_decrypt(in,out,(int)rails);
        else    railfence_encrypt(in,out,(int)rails);
        goto done;
    }
    if(!strcmp(method,"columnar")){
        if(dec) columnar_decrypt(in,out,key);
        else    columnar_encrypt(in,out,key);
        goto done;
    }
    if(!strcmp(method,"adfgvx")){
        if(dec) adfgvx_decrypt(in,out,key); else adfgvx_encrypt(in,out,key); goto done;
    }
    if(!strcmp(method,"double")){
        if(dec) double_decrypt(in,out,key); else double_encrypt(in,out,key); goto done;
    }
    if(!strcmp(method,"enigma")){
        enigma_cipher(in,out,key); goto done; /* self-inverse */
    }
    if(!strcmp(method,"vernam")){
        vernam_cipher(in,out,key); goto done; /* self-inverse */
    }

    /* ── Pure-C modern ─────────────────────────────────────────────────── */
    if(!strcmp(method,"atbash")) { atbash_cipher(in,out); goto done; }
    if(!strcmp(method,"xor"))    { xor_cipher(in,out,key); goto done; }
    if(!strcmp(method,"rot13"))  { rot13_cipher(in,out); goto done; }
    if(!strcmp(method,"rc4"))    { rc4_cipher(in,out,key); goto done; }
    if(!strcmp(method,"caesar")) {
        char *e; long sh=strtol(key,&e,10);
        if(*e) die("Caesar key must be an integer (e.g. -k \"13\").");
        if(dec) caesar_decrypt(in,out,(int)sh); else caesar_encrypt(in,out,(int)sh);
        goto done;
    }
    if(!strcmp(method,"vigenere")) { vigenere_cipher(in,out,key,dec); goto done; }

    /* ── OpenSSL stream ────────────────────────────────────────────────── */
    if(!strcmp(method,"chacha20")){
        const EVP_CIPHER *c=EVP_get_cipherbyname("chacha20");
        if(!c) die("ChaCha20 not available.");
        if(dec) ossl_cbc_decrypt(in,out,key,c); else ossl_cbc_encrypt(in,out,key,c);
        goto done;
    }
    if(!strcmp(method,"chacha20-poly1305")){
        const EVP_CIPHER *c=EVP_get_cipherbyname("chacha20-poly1305");
        if(!c) die("ChaCha20-Poly1305 not available.");
        if(dec) ossl_aead_decrypt(in,out,key,c); else ossl_aead_encrypt(in,out,key,c);
        goto done;
    }

    /* ── OpenSSL table ─────────────────────────────────────────────────── */
    for(const CipherEntry *e=CIPHER_TABLE;e->name;e++){
        if(!strcmp(method,e->name)){
            const EVP_CIPHER *c=EVP_get_cipherbyname(e->ossl_name);
            if(!c){fprintf(stderr,"[ERROR] \"%s\" not available in this OpenSSL build.\n",method);
                   fclose(in);if(out)fclose(out);return 1;}
            if(e->is_aead){
                if(dec) ossl_aead_decrypt(in,out,key,c); else ossl_aead_encrypt(in,out,key,c);
            } else {
                if(dec) ossl_cbc_decrypt(in,out,key,c); else ossl_cbc_encrypt(in,out,key,c);
            }
            goto done;
        }
    }

    /* Unknown */
    fclose(in); if(out)fclose(out);
    fprintf(stderr,"[ERROR] Unknown method \"%s\".\n"
                   "        Run with -h to see all available methods.\n",method);
    return 1;

done:
    if(ferror(in))         {perror("read error"); fclose(in);if(out)fclose(out);return 1;}
    if(out&&ferror(out))   {perror("write error");fclose(in);fclose(out);       return 1;}
    fclose(in); if(out)fclose(out);
    printf("[OK] %s '%s'  ->  '%s'  (method: %s)\n",
           dec?"Decrypted":"Encrypted",ipath,opath,method);
    return 0;
}
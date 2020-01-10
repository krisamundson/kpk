# Overview

Kris Password Keystore

Simple key-value store for automation and helping minimize environment
variable exposure.

This provides the glue between gpg-agent, which already contains a
time-limited cached decrypted private key, and a k/v store for
populating environment variables.

Coupled with direnv to pick and choose which environment variables
are at play, one can limit the exposure of tokens and other potential
security credentials in use at a time.

# Prerequisites

You must first have a working gpg environment. Such as:

    `gpg -d foo.gpg`

That should work before kpk is useful.

# Install

    `make`

1. sudo copies `kpk.py` to `/usr/local/bin/kpk`.
2. Shebang is modified to use /usr/local/bin/python3 runtime.

# Password

Using the gpg-agent that is pre-primed to decrypt files without a
passphrase prompt, gpg is called to obtain text in the file
`password.gpg`. Using rstrip(), all whitspaces on the right
are removed. This text is the secret key.

    $HOME/.kpk/password.gpg

# Password Strength

In order to catch weak passwords (and empty ones), we use the
*py-password-strength* module to test them before use. 

## From https://github.com/kolypto/py-password-strength

Normalization is done in the following fashion:

    If entropy_bits <= weak_bits -- linear in range{0.0 .. 0.33} (weak)
    If entropy_bits <= weak_bits*2 -- almost linear in range{0.33 .. 0.66} (medium)
    If entropy_bits > weak_bits*3 -- asymptotic towards 1.0 (strong)

# Encryption

This password is then used to generate a url-friendly base64
of 32 bytes object that is used as the key for encrypting and
decrypting the values. This { key: value } dictionary is then
written to a JSON file on disk in the default kpk directory:

    $HOME/.kpk/secrets.json

Keys are not encrypted in this JSON file, only values.

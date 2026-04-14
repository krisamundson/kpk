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

    gpg -d foo.gpg

That should work before kpk is useful.

# Install

    pip install -e .

This installs kpk in editable mode into your active Python virtual environment, making the `kpk` command available on your PATH.

# Usage

    kpk set <key> <value>       # store a secret
    kpk set <key> --prompt      # store a secret (hidden input)
    kpk get <key>               # copy secret to clipboard
    kpk get <key> --out         # print secret to stdout
    kpk delete <key>            # remove a secret
    kpk ls                      # list all keys with timestamps
    kpk search <pattern>        # case-insensitive key name search
    kpk export                  # export all secrets as cleartext JSON
    kpk export --file out.json  # export to file
    kpk import --file in.json   # import from JSON file
    kpk import --yaml -f f.yaml # import user/pass pairs from YAML
    kpk --version               # show version

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

## Two layers

1. **File-level**: The entire database is GPG-encrypted on disk as
   `$HOME/.kpk/secrets.json.gpg` (ASCII-armored, encrypted to
   `--default-recipient-self`).

2. **Value-level**: Individual values are Fernet-encrypted using a key
   derived from the password in `password.gpg` via HKDF-SHA256.

Keys are visible in the decrypted JSON but not on disk. The DB
directory can be overridden via `KPK_DBDIR` environment variable.

## DB format (v3)

Entries include timestamps:

    {
        "__version__": "3",
        "mykey": {
            "value": "<fernet ciphertext>",
            "updated": "2026-04-13T15:30:00Z"
        }
    }

Timestamps are used by `ls`, `export`, and `import` (newer entry
wins on conflict).

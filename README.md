# `axum-htpasswd`

Even the simplest web applications require the authentication of users for
various usages. The goal of this package is to allow this in the simplest way
possible that has been around since forever: Using a htpasswd file.

`axum-htpasswd` supports files with password in plaintext (not recommended), or
hashed using Argon2id (recommended), or scrypt.

By enabling the feature `cli`, the built application will support generating
htpasswd files.

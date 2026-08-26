# InfiniGit CLI

Browser-linked command-line authentication for InfiniGit.

```bash
cargo install --path .
infinigit auth login
infinigit auth status
infinigit auth link-device --name work-laptop --label "Work laptop"
```

The CLI uses `icp identity link web` to obtain an Internet Identity delegation
for the InfiniGit app origin, stores the session key using ICP CLI's selected
storage backend, and configures Git to select that identity only for InfiniGit
operations. It requires `git` and `icp` on `PATH`.

Identity keys use ICP CLI's password-protected storage by default so the CLI
also works on Linux servers, containers, and other sessions without a desktop
Secret Service. ICP CLI will prompt for a password of at least eight characters.
On a desktop with a working system keyring, opt into it with
`--storage keyring`. Plaintext storage should only be used for disposable local
development identities.

`link-device` instead creates an independent local key and prints a short-lived
pairing code. Review that code in the website settings to attach the device to
your existing account with repository read/write access. Use `--read-only` for
a clone-only device. The device key can be revoked without affecting Internet
Identity or other machines.

This directory is an independent Cargo package and can be extracted into its
own repository without source-layout changes.

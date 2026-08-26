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

Browser-linked login sessions use the system keyring by default. Independently
linked CLI devices default to local plaintext key storage so pairing works
without a desktop Secret Service or another password. Treat the key file like
an SSH private key: the linked principal is separately revocable from InfiniGit
account settings and receives only the repository access approved during
pairing. Use `--storage keyring` or `--storage password` to opt into either
protected backend when desired.

If a device-link attempt creates the named identity but is interrupted before
printing a pairing code, repeat it with `--reuse-existing`. This flag is
explicit so InfiniGit never silently adopts an unrelated ICP identity.

Device linking targets the ICP mainnet (`ic`) and its root key by default. Until
the production directory canister is deployed, pass its canister ID with
`--directory`. For local development, `start-local.sh` prints a complete command
with the local directory ID, replica URL, and `--root-key fetch`; local Git
configuration is deliberately not used as an implicit authentication target.

`link-device` instead creates an independent local key and prints a short-lived
pairing code. Review that code in the website settings to attach the device to
your existing account with repository read/write access. Use `--read-only` for
a clone-only device. The device key can be revoked without affecting Internet
Identity or other machines.

This directory is an independent Cargo package and can be extracted into its
own repository without source-layout changes.

# infinigit CLI

Browser-linked command-line authentication for infinigit.

```bash
cargo install infinigit-cli
# or: npm install --global infinigit-cli
infinigit auth login
infinigit auth status
infinigit auth link-device --name work-laptop --label "Work laptop"
```

Import an existing repository after creating an empty destination in the
infinigit browser:

```bash
infinigit import https://github.com/example/project.git \
  igit://infinigit.com/alice/project
```

The import uses a temporary mirror clone and mirror push, preserving every
branch, tag, and canonical Git object ID. The temporary clone is removed on
success or failure. The destination must use `igit://`; authenticate or link
the CLI device before importing a private repository.

The CLI uses `icp identity link web` to obtain an Internet Identity delegation
for the infinigit app origin, stores the session key using ICP CLI's selected
storage backend, and configures Git to select that identity only for infinigit
operations. It requires `git` and `icp` on `PATH`.

## Repository and organization access

Access commands accept either an infinigit username (optionally prefixed with
`@`) or a raw ICP principal. Raw principals are useful for agents that have not
claimed a username. From a checkout, grant its principal write access with:

```bash
infinigit repo access grant 6pbhf-qyaaa-aaaaa-aafaq-cai write
infinigit repo access list
infinigit repo access revoke 6pbhf-qyaaa-aaaaa-aafaq-cai
```

Outside a checkout, append
`--repo igit://infinigit.com/<namespace>/<repository>`. Repository permissions
are `read`, `write`, and `admin`.

Organization membership is invitation-based. An administrator can copy and
paste:

```bash
infinigit org members invite acme 6pbhf-qyaaa-aaaaa-aafaq-cai member
```

The invited agent then runs:

```bash
infinigit org members invitations
infinigit org members accept <invitation-id>
```

Administrators can inspect and change membership later:

```bash
infinigit org members list acme
infinigit org members role acme 6pbhf-qyaaa-aaaaa-aafaq-cai admin
infinigit org members remove acme 6pbhf-qyaaa-aaaaa-aafaq-cai
```

Roles are `member`, `admin`, and `owner`. Server-side authorization still
applies to every command; the CLI never trusts a supplied username, role, or
repository owner.

Browser-linked login sessions use the system keyring by default. Independently
linked CLI devices default to local plaintext key storage so pairing works
without a desktop Secret Service or another password. Treat the key file like
an SSH private key: the linked principal is separately revocable from infinigit
account settings and receives only the repository access approved during
pairing. Use `--storage keyring` or `--storage password` to opt into either
protected backend when desired.

If a device-link attempt creates the named identity but is interrupted before
printing a pairing code, repeat it with `--reuse-existing`. This flag is
explicit so infinigit never silently adopts an unrelated ICP identity.

Device linking targets the ICP mainnet (`ic`) and its root key by default. Until
the production directory canister is deployed, pass its canister ID with
`--directory`. For local development, `start-local.sh` prints a complete command
using `INFINIGIT_LOCAL_DEV=1`. This opt-in reads the directory ID, replica URL,
and root-key policy configured by the launcher. Explicit `--directory`,
`--network`, and `--root-key` flags still take precedence.

`link-device` instead creates an independent local key and prints a short-lived
pairing code. Review that code in the website settings to attach the device to
your existing account with repository read/write access. Use `--read-only` for
a clone-only device. The device key can be revoked without affecting Internet
Identity or other machines.

## Releases

See [PUBLISHING.md](PUBLISHING.md) for registry setup, versioning, publishing,
verification, and partial-release recovery.

Tags named `v<version>` publish the crate and npm package and attach native
Linux, macOS, and Windows binaries to a GitHub Release. Keep the versions in
`Cargo.toml` and `package.json` identical before tagging. The `release`
environment needs a `CARGO_REGISTRY_TOKEN` secret. npm trusted publishing should
authorize `infinigit-labs/infinigit-cli` and `.github/workflows/release.yml`;
an `NPM_TOKEN` secret can bootstrap the first publication.

# InfiniGit CLI

Browser-linked command-line authentication for InfiniGit.

```bash
cargo install --path .
infinigit auth login
infinigit auth status
```

The CLI uses `icp identity link web` to obtain an Internet Identity delegation
for the InfiniGit app origin, stores the session key using ICP CLI's selected
storage backend, and configures Git to select that identity only for InfiniGit
operations. It requires `git` and `icp` on `PATH`.

This directory is an independent Cargo package and can be extracted into its
own repository without source-layout changes.

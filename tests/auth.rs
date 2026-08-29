use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
use tempfile::TempDir;

fn path_with(directory: &Path) -> String {
    format!(
        "{}:{}",
        directory.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

#[test]
fn login_status_and_logout_use_icp_web_delegation_and_git_identity_config() {
    let temp = TempDir::new().unwrap();
    let icp = temp.path().join("icp");
    let log = temp.path().join("icp.log");
    let git_config = temp.path().join("gitconfig");
    fs::write(
        &icp,
        r#"#!/usr/bin/env bash
set -e
printf '%s\n' "$*" >>"$INFINIGIT_TEST_ICP_LOG"
if [[ "$*" == 'identity list -q' ]]; then exit 0; fi
if [[ "$*" == *'identity principal'* ]]; then printf 'aaaaa-aa\n'; fi
"#,
    )
    .unwrap();
    fs::set_permissions(&icp, fs::Permissions::from_mode(0o755)).unwrap();
    let binary = env!("CARGO_BIN_EXE_infinigit");
    let common = |command: &mut Command| {
        command
            .env("PATH", path_with(temp.path()))
            .env("GIT_CONFIG_GLOBAL", &git_config)
            .env("INFINIGIT_TEST_ICP_LOG", &log);
    };

    let mut login = Command::new(binary);
    common(&mut login);
    let output = login
        .args([
            "auth",
            "login",
            "--name",
            "browser",
            "--auth",
            "https://id.ai",
            "--app",
            "https://code.example",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("aaaaa-aa"));
    let calls = fs::read_to_string(&log).unwrap();
    assert!(calls.contains("identity link web browser --auth https://id.ai --app https://code.example --storage keyring"));
    assert!(calls.contains("identity principal --identity browser"));
    let configured = Command::new("git")
        .args(["config", "--global", "--get", "infinigit.identity"])
        .env("GIT_CONFIG_GLOBAL", &git_config)
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&configured.stdout).trim(),
        "browser"
    );

    let mut status = Command::new(binary);
    common(&mut status);
    assert!(
        status
            .args(["auth", "status", "--name", "browser"])
            .status()
            .unwrap()
            .success()
    );

    let mut logout = Command::new(binary);
    common(&mut logout);
    assert!(
        logout
            .args(["auth", "logout", "--name", "browser"])
            .status()
            .unwrap()
            .success()
    );
    let calls = fs::read_to_string(&log).unwrap();
    assert!(calls.contains("identity delete browser"));
    let configured = Command::new("git")
        .args(["config", "--global", "--get", "infinigit.identity"])
        .env("GIT_CONFIG_GLOBAL", &git_config)
        .status()
        .unwrap();
    assert!(!configured.success());
}

#[test]
fn login_refuses_to_replace_an_existing_linked_identity() {
    let temp = TempDir::new().unwrap();
    let icp = temp.path().join("icp");
    fs::write(&icp, "#!/usr/bin/env bash\nif [[ \"$*\" == 'identity list -q' ]]; then printf 'infinigit\\n'; fi\n").unwrap();
    fs::set_permissions(&icp, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_infinigit"))
        .args(["auth", "login"])
        .env("PATH", path_with(temp.path()))
        .env("GIT_CONFIG_GLOBAL", temp.path().join("gitconfig"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already exists"));
}

#[test]
fn logout_cannot_delete_an_unrelated_icp_identity() {
    let temp = TempDir::new().unwrap();
    let icp = temp.path().join("icp");
    fs::write(&icp, "#!/usr/bin/env bash\nexit 99\n").unwrap();
    fs::set_permissions(&icp, fs::Permissions::from_mode(0o755)).unwrap();
    let config = temp.path().join("gitconfig");
    assert!(
        Command::new("git")
            .args(["config", "--global", "infinigit.identity", "infinigit"])
            .env("GIT_CONFIG_GLOBAL", &config)
            .status()
            .unwrap()
            .success()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_infinigit"))
        .args(["auth", "logout", "--name", "valuable-wallet"])
        .env("PATH", path_with(temp.path()))
        .env("GIT_CONFIG_GLOBAL", config)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to delete"));
}

#[test]
fn independent_device_login_creates_a_scoped_pairing_request() {
    let temp = TempDir::new().unwrap();
    let icp = temp.path().join("icp");
    let log = temp.path().join("icp.log");
    fs::write(&icp, r#"#!/usr/bin/env bash
set -e
printf '%s\n' "$*" >>"$INFINIGIT_TEST_ICP_LOG"
if [[ "$*" == 'identity list -q' ]]; then exit 0; fi
if [[ "$*" == *'request_device_link'* ]]; then printf 'variant { ok = record { id = 42 : nat } }\n'; fi
"#).unwrap();
    fs::set_permissions(&icp, fs::Permissions::from_mode(0o755)).unwrap();
    let config = temp.path().join("gitconfig");
    for (key, value) in [
        ("infinigit.directory-canister", "aaaaa-aa"),
        ("infinigit.network", "http://127.0.0.1:4943"),
        ("infinigit.root-key", "fetch"),
        ("infinigit.app-origin", "http://frontend.localhost:4943"),
    ] {
        assert!(
            Command::new("git")
                .args(["config", "--global", key, value])
                .env("GIT_CONFIG_GLOBAL", &config)
                .status()
                .unwrap()
                .success()
        );
    }
    let output = Command::new(env!("CARGO_BIN_EXE_infinigit"))
        .args([
            "auth",
            "link-device",
            "--name",
            "laptop",
            "--label",
            "Work laptop",
            "--read-only",
            "--storage",
            "plaintext",
            "--directory",
            "aaaaa-aa",
            "--network",
            "http://127.0.0.1:4943",
            "--root-key",
            "fetch",
        ])
        .env("PATH", path_with(temp.path()))
        .env("GIT_CONFIG_GLOBAL", &config)
        .env("INFINIGIT_TEST_ICP_LOG", &log)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("42:"));
    assert!(stdout.contains("/#/settings/devices"));
    let calls = fs::read_to_string(&log).unwrap();
    assert!(calls.contains("identity new laptop --storage plaintext"));
    assert!(calls.contains("request_device_link"));
    assert!(calls.contains("true, false, null"));
    assert!(calls.contains("--identity laptop --network http://127.0.0.1:4943 --root-key fetch"));
}

#[test]
fn device_link_defaults_to_passwordless_local_storage() {
    let temp = TempDir::new().unwrap();
    let icp = temp.path().join("icp");
    let log = temp.path().join("icp.log");
    fs::write(&icp, r#"#!/usr/bin/env bash
set -e
printf '%s\n' "$*" >>"$INFINIGIT_TEST_ICP_LOG"
if [[ "$*" == 'identity list -q' ]]; then exit 0; fi
if [[ "$*" == *'request_device_link'* ]]; then printf 'variant { ok = record { id = 7 : nat } }\n'; fi
"#).unwrap();
    fs::set_permissions(&icp, fs::Permissions::from_mode(0o755)).unwrap();
    let config = temp.path().join("gitconfig");
    for (key, value) in [
        ("infinigit.directory-canister", "aaaaa-aa"),
        ("infinigit.network", "http://127.0.0.1:4943"),
        ("infinigit.root-key", "fetch"),
    ] {
        assert!(
            Command::new("git")
                .args(["config", "--global", key, value])
                .env("GIT_CONFIG_GLOBAL", &config)
                .status()
                .unwrap()
                .success()
        );
    }
    let output = Command::new(env!("CARGO_BIN_EXE_infinigit"))
        .args([
            "auth",
            "link-device",
            "--name",
            "headless",
            "--label",
            "Headless host",
            "--directory",
            "aaaaa-aa",
        ])
        .env("PATH", path_with(temp.path()))
        .env("GIT_CONFIG_GLOBAL", &config)
        .env("INFINIGIT_TEST_ICP_LOG", &log)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let calls = fs::read_to_string(log).unwrap();
    assert!(calls.contains("identity new headless --storage plaintext"));
    assert!(calls.contains("--network ic --root-key mainnet"));
}

#[test]
fn local_development_mode_uses_launcher_git_configuration() {
    let temp = TempDir::new().unwrap();
    let icp = temp.path().join("icp");
    let log = temp.path().join("icp.log");
    fs::write(&icp, r#"#!/usr/bin/env bash
set -e
printf '%s\n' "$*" >>"$INFINIGIT_TEST_ICP_LOG"
if [[ "$*" == 'identity list -q' ]]; then exit 0; fi
if [[ "$*" == *'request_device_link'* ]]; then printf 'variant { ok = record { id = 8 : nat } }\n'; fi
"#).unwrap();
    fs::set_permissions(&icp, fs::Permissions::from_mode(0o755)).unwrap();
    let config = temp.path().join("gitconfig");
    for (key, value) in [
        ("infinigit.directory-canister", "local-directory"),
        ("infinigit.network", "http://127.0.0.1:4943"),
        ("infinigit.root-key", "fetch"),
    ] {
        assert!(
            Command::new("git")
                .args(["config", "--global", key, value])
                .env("GIT_CONFIG_GLOBAL", &config)
                .status()
                .unwrap()
                .success()
        );
    }
    let output = Command::new(env!("CARGO_BIN_EXE_infinigit"))
        .args([
            "auth",
            "link-device",
            "--name",
            "easy-local",
            "--label",
            "Easy local",
        ])
        .env("INFINIGIT_LOCAL_DEV", "1")
        .env("PATH", path_with(temp.path()))
        .env("GIT_CONFIG_GLOBAL", &config)
        .env("INFINIGIT_TEST_ICP_LOG", &log)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let calls = fs::read_to_string(&log).unwrap();
    assert!(calls.contains("canister call local-directory request_device_link"));
    assert!(calls.contains("--network http://127.0.0.1:4943 --root-key fetch"));

    let output = Command::new(env!("CARGO_BIN_EXE_infinigit"))
        .args([
            "auth",
            "link-device",
            "--name",
            "explicit-local",
            "--directory",
            "explicit-directory",
            "--network",
            "http://localhost:8000",
            "--root-key",
            "mainnet",
        ])
        .env("INFINIGIT_LOCAL_DEV", "true")
        .env("PATH", path_with(temp.path()))
        .env("GIT_CONFIG_GLOBAL", &config)
        .env("INFINIGIT_TEST_ICP_LOG", &log)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let calls = fs::read_to_string(log).unwrap();
    assert!(calls.contains("canister call explicit-directory request_device_link"));
    assert!(calls.contains("--network http://localhost:8000 --root-key mainnet"));
}

#[test]
fn device_link_can_resume_with_an_identity_created_by_a_failed_attempt() {
    let temp = TempDir::new().unwrap();
    let icp = temp.path().join("icp");
    let log = temp.path().join("icp.log");
    fs::write(&icp, r#"#!/usr/bin/env bash
set -e
printf '%s\n' "$*" >>"$INFINIGIT_TEST_ICP_LOG"
if [[ "$*" == 'identity list -q' ]]; then printf 'my-laptop\n'; fi
if [[ "$*" == *'request_device_link'* ]]; then printf 'variant { ok = record { id = 9 : nat } }\n'; fi
"#).unwrap();
    fs::set_permissions(&icp, fs::Permissions::from_mode(0o755)).unwrap();
    let config = temp.path().join("gitconfig");
    for (key, value) in [
        ("infinigit.directory-canister", "aaaaa-aa"),
        ("infinigit.network", "http://127.0.0.1:4943"),
        ("infinigit.root-key", "fetch"),
    ] {
        assert!(
            Command::new("git")
                .args(["config", "--global", key, value])
                .env("GIT_CONFIG_GLOBAL", &config)
                .status()
                .unwrap()
                .success()
        );
    }
    let output = Command::new(env!("CARGO_BIN_EXE_infinigit"))
        .args([
            "auth",
            "link-device",
            "--name",
            "my-laptop",
            "--label",
            "My laptop",
            "--reuse-existing",
            "--directory",
            "aaaaa-aa",
            "--network",
            "http://127.0.0.1:4943",
            "--root-key",
            "fetch",
        ])
        .env("PATH", path_with(temp.path()))
        .env("GIT_CONFIG_GLOBAL", &config)
        .env("INFINIGIT_TEST_ICP_LOG", &log)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let calls = fs::read_to_string(log).unwrap();
    assert!(!calls.contains("identity new my-laptop"));
    assert!(calls.contains("--network http://127.0.0.1:4943 --root-key fetch"));
}

#[test]
fn device_link_requires_a_directory_until_mainnet_is_deployed() {
    let temp = TempDir::new().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_infinigit"))
        .args(["auth", "link-device", "--name", "mainnet-device"])
        .env_remove("INFINIGIT_DIRECTORY_CANISTER_ID")
        .env("PATH", path_with(temp.path()))
        .env("GIT_CONFIG_GLOBAL", temp.path().join("gitconfig"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("pass --directory"));

    let output = Command::new(env!("CARGO_BIN_EXE_infinigit"))
        .args(["auth", "link-device", "--name", "invalid-local-mode"])
        .env("INFINIGIT_LOCAL_DEV", "yes")
        .env("PATH", path_with(temp.path()))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must be 1, true, 0, or false"));
}

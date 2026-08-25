use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
use tempfile::TempDir;

fn path_with(directory: &Path) -> String {
    format!("{}:{}", directory.display(), std::env::var("PATH").unwrap_or_default())
}

#[test]
fn login_status_and_logout_use_icp_web_delegation_and_git_identity_config() {
    let temp = TempDir::new().unwrap();
    let icp = temp.path().join("icp");
    let log = temp.path().join("icp.log");
    let git_config = temp.path().join("gitconfig");
    fs::write(&icp, r#"#!/usr/bin/env bash
set -e
printf '%s\n' "$*" >>"$INFINIGIT_TEST_ICP_LOG"
if [[ "$*" == 'identity list -q' ]]; then exit 0; fi
if [[ "$*" == *'identity principal'* ]]; then printf 'aaaaa-aa\n'; fi
"#).unwrap();
    fs::set_permissions(&icp, fs::Permissions::from_mode(0o755)).unwrap();
    let binary = env!("CARGO_BIN_EXE_infinigit");
    let common = |command: &mut Command| {
        command.env("PATH", path_with(temp.path()))
            .env("GIT_CONFIG_GLOBAL", &git_config)
            .env("INFINIGIT_TEST_ICP_LOG", &log);
    };

    let mut login = Command::new(binary);
    common(&mut login);
    let output = login.args(["auth", "login", "--name", "browser", "--auth", "https://id.ai", "--app", "https://code.example"]).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("aaaaa-aa"));
    let calls = fs::read_to_string(&log).unwrap();
    assert!(calls.contains("identity link web browser --auth https://id.ai --app https://code.example --storage keyring"));
    assert!(calls.contains("identity principal --identity browser"));
    let configured = Command::new("git").args(["config", "--global", "--get", "infinigit.identity"]).env("GIT_CONFIG_GLOBAL", &git_config).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&configured.stdout).trim(), "browser");

    let mut status = Command::new(binary);
    common(&mut status);
    assert!(status.args(["auth", "status", "--name", "browser"]).status().unwrap().success());

    let mut logout = Command::new(binary);
    common(&mut logout);
    assert!(logout.args(["auth", "logout", "--name", "browser"]).status().unwrap().success());
    let calls = fs::read_to_string(&log).unwrap();
    assert!(calls.contains("identity delete browser"));
    let configured = Command::new("git").args(["config", "--global", "--get", "infinigit.identity"]).env("GIT_CONFIG_GLOBAL", &git_config).status().unwrap();
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
        .output().unwrap();
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
    assert!(Command::new("git").args(["config", "--global", "infinigit.identity", "infinigit"]).env("GIT_CONFIG_GLOBAL", &config).status().unwrap().success());
    let output = Command::new(env!("CARGO_BIN_EXE_infinigit"))
        .args(["auth", "logout", "--name", "valuable-wallet"])
        .env("PATH", path_with(temp.path()))
        .env("GIT_CONFIG_GLOBAL", config)
        .output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to delete"));
}

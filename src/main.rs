//! InfiniGit command-line authentication and configuration.

use std::{
    env,
    fs::File,
    io::Read,
    process::{Command, ExitCode, Stdio},
};

const DEFAULT_IDENTITY: &str = "infinigit";
const DEFAULT_AUTH: &str = "https://id.ai";
const DEFAULT_APP: &str = "https://infinigit.com";
const DEFAULT_NETWORK: &str = "ic";
const DEFAULT_DIRECTORY: &str = "vc3gg-2qaaa-aaaae-qklda-cai";

#[derive(Debug, PartialEq, Eq)]
enum AuthCommand {
    Import {
        source: String,
        destination: String,
    },
    Login {
        name: String,
        auth: String,
        app: String,
        storage: String,
    },
    Status {
        name: String,
    },
    Reauth {
        name: String,
    },
    Logout {
        name: String,
    },
    LinkDevice {
        name: String,
        label: String,
        storage: String,
        read_only: bool,
        reuse_existing: bool,
        directory: Option<String>,
        network: String,
        root_key: String,
    },
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn value(args: &[String], flag: &str, fallback: &str) -> Result<String, String> {
    match args.iter().position(|arg| arg == flag) {
        Some(index) => args
            .get(index + 1)
            .cloned()
            .ok_or_else(|| format!("{flag} requires a value")),
        None => Ok(fallback.to_owned()),
    }
}

fn local_development() -> Result<bool, String> {
    match env::var("INFINIGIT_LOCAL_DEV").ok().as_deref() {
        None | Some("") | Some("0") | Some("false") => Ok(false),
        Some("1") | Some("true") => Ok(true),
        Some(_) => Err("INFINIGIT_LOCAL_DEV must be 1, true, 0, or false".into()),
    }
}

fn parse(args: &[String]) -> Result<AuthCommand, String> {
    if args.first().map(String::as_str) == Some("import") {
        let source = args
            .get(1)
            .filter(|value| !value.starts_with('-'))
            .cloned()
            .ok_or("usage: infinigit import <source-git-url> <igit://host/namespace/repository>")?;
        let destination = args
            .get(2)
            .filter(|value| value.starts_with("igit://") && !value.contains(char::is_whitespace))
            .cloned()
            .ok_or("import destination must be an igit:// repository URL")?;
        if args.len() != 3 {
            return Err(
                "usage: infinigit import <source-git-url> <igit://host/namespace/repository>"
                    .into(),
            );
        }
        return Ok(AuthCommand::Import {
            source,
            destination,
        });
    }
    if args.first().map(String::as_str) != Some("auth") {
        return Err("usage: infinigit <auth|import> [options]".into());
    }
    let action = args
        .get(1)
        .map(String::as_str)
        .ok_or("missing auth command")?;
    let name = value(args, "--name", DEFAULT_IDENTITY)?;
    if !valid_name(&name) {
        return Err("invalid identity name".into());
    }
    match action {
        "login" => {
            let auth = value(
                args,
                "--auth",
                &env::var("INFINIGIT_AUTH_ORIGIN").unwrap_or_else(|_| DEFAULT_AUTH.into()),
            )?;
            let app = value(
                args,
                "--app",
                &env::var("INFINIGIT_APP_ORIGIN").unwrap_or_else(|_| DEFAULT_APP.into()),
            )?;
            let storage = value(args, "--storage", "keyring")?;
            if !matches!(storage.as_str(), "keyring" | "password" | "plaintext") {
                return Err("invalid identity storage".into());
            }
            if !(auth.starts_with("https://")
                || auth.starts_with("http://localhost")
                || auth.starts_with("http://127.0.0.1"))
            {
                return Err("invalid auth origin".into());
            }
            if !(app.starts_with("https://")
                || app.starts_with("http://localhost")
                || app.starts_with("http://127.0.0.1"))
            {
                return Err("invalid app origin".into());
            }
            Ok(AuthCommand::Login {
                name,
                auth,
                app,
                storage,
            })
        }
        "status" => Ok(AuthCommand::Status { name }),
        "reauth" => Ok(AuthCommand::Reauth { name }),
        "logout" => Ok(AuthCommand::Logout { name }),
        "link-device" => {
            let local_dev = local_development()?;
            let label = value(args, "--label", "CLI device")?;
            let storage = value(args, "--storage", "plaintext")?;
            let directory_fallback = env::var("INFINIGIT_DIRECTORY_CANISTER_ID")
                .ok()
                .or_else(|| {
                    local_dev
                        .then(|| {
                            run(
                                "git",
                                &[
                                    "config",
                                    "--global",
                                    "--get",
                                    "infinigit.directory-canister",
                                ],
                            )
                            .ok()
                        })
                        .flatten()
                })
                .unwrap_or_else(|| {
                    if local_dev {
                        String::new()
                    } else {
                        DEFAULT_DIRECTORY.into()
                    }
                });
            let network_fallback = env::var("INFINIGIT_NETWORK")
                .ok()
                .or_else(|| {
                    local_dev
                        .then(|| {
                            run("git", &["config", "--global", "--get", "infinigit.network"]).ok()
                        })
                        .flatten()
                })
                .unwrap_or_else(|| {
                    if local_dev {
                        "http://127.0.0.1:4943".into()
                    } else {
                        DEFAULT_NETWORK.into()
                    }
                });
            let root_key_fallback = env::var("INFINIGIT_ROOT_KEY")
                .ok()
                .or_else(|| {
                    local_dev
                        .then(|| {
                            run(
                                "git",
                                &["config", "--global", "--get", "infinigit.root-key"],
                            )
                            .ok()
                        })
                        .flatten()
                })
                .unwrap_or_else(|| {
                    if local_dev {
                        "fetch".into()
                    } else {
                        "mainnet".into()
                    }
                });
            let directory = value(args, "--directory", &directory_fallback)?;
            let network = value(args, "--network", &network_fallback)?;
            let root_key = value(args, "--root-key", &root_key_fallback)?;
            if label.is_empty()
                || label.len() > 80
                || !label.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'-' | b'_' | b'.')
                })
            {
                return Err("invalid device label".into());
            }
            if !matches!(storage.as_str(), "keyring" | "password" | "plaintext") {
                return Err("invalid identity storage".into());
            }
            if network.is_empty()
                || !(matches!(root_key.as_str(), "mainnet" | "fetch")
                    || root_key.len() == 266
                        && root_key.bytes().all(|byte| byte.is_ascii_hexdigit()))
            {
                return Err("invalid network or root key".into());
            }
            Ok(AuthCommand::LinkDevice {
                name,
                label,
                storage,
                read_only: args.iter().any(|arg| arg == "--read-only"),
                reuse_existing: args.iter().any(|arg| arg == "--reuse-existing"),
                directory: (!directory.is_empty()).then_some(directory),
                network,
                root_key,
            })
        }
        _ => Err("usage: infinigit auth <login|status|reauth|logout> [options]".into()),
    }
}

fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("cannot run {program}: {error}"))?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(if message.is_empty() {
            format!("{program} failed")
        } else {
            message
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn run_with_prompt(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|error| format!("cannot run {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!("{program} failed"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn run_interactive(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|error| format!("cannot run {program}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} authentication failed"))
    }
}

fn configure(name: &str, auth: Option<&str>, app: Option<&str>) -> Result<(), String> {
    run("git", &["config", "--global", "infinigit.identity", name])?;
    if let Some(auth) = auth {
        run(
            "git",
            &["config", "--global", "infinigit.auth-origin", auth],
        )?;
    }
    if let Some(app) = app {
        run("git", &["config", "--global", "infinigit.app-origin", app])?;
    }
    Ok(())
}

fn execute(command: AuthCommand) -> Result<String, String> {
    match command {
        AuthCommand::Import {
            source,
            destination,
        } => {
            let checkout = tempfile::Builder::new()
                .prefix("infinigit-import-")
                .tempdir()
                .map_err(|error| format!("cannot create temporary import directory: {error}"))?;
            let repository = checkout.path().join("repository.git");
            let repository_path = repository
                .to_str()
                .ok_or("temporary import path is not valid UTF-8")?;
            run_interactive(
                "git",
                &["clone", "--mirror", "--", &source, repository_path],
            )
            .map_err(|error| format!("source clone failed: {error}"))?;
            run_interactive(
                "git",
                &[
                    "--git-dir",
                    repository_path,
                    "push",
                    "--mirror",
                    "--",
                    &destination,
                ],
            )
            .map_err(|error| format!("InfiniGit push failed: {error}"))?;
            Ok(format!(
                "Imported every branch and tag from {source} into {destination}."
            ))
        }
        AuthCommand::Login {
            name,
            auth,
            app,
            storage,
        } => {
            let identities = run("icp", &["identity", "list", "-q"])?;
            if identities.lines().any(|existing| existing == name) {
                return Err(format!(
                    "identity '{name}' already exists; use 'infinigit auth reauth --name {name}' or log out first"
                ));
            }
            run_interactive(
                "icp",
                &[
                    "identity",
                    "link",
                    "web",
                    &name,
                    "--auth",
                    &auth,
                    "--app",
                    &app,
                    "--storage",
                    &storage,
                ],
            )?;
            configure(&name, Some(&auth), Some(&app))?;
            let principal = run("icp", &["identity", "principal", "--identity", &name])?;
            Ok(format!(
                "Signed in to InfiniGit as {principal}. Git will use the linked identity '{name}'."
            ))
        }
        AuthCommand::Status { name } => {
            let principal = run("icp", &["identity", "principal", "--identity", &name])?;
            Ok(format!(
                "InfiniGit identity: {name}\nPrincipal: {principal}"
            ))
        }
        AuthCommand::Reauth { name } => {
            run_interactive("icp", &["identity", "reauth", &name])?;
            configure(&name, None, None)?;
            let principal = run("icp", &["identity", "principal", "--identity", &name])?;
            Ok(format!("InfiniGit delegation refreshed for {principal}."))
        }
        AuthCommand::Logout { name } => {
            let configured = run(
                "git",
                &["config", "--global", "--get", "infinigit.identity"],
            )?;
            if configured != name {
                return Err(format!(
                    "refusing to delete identity '{name}' because it is not the configured InfiniGit identity"
                ));
            }
            run("icp", &["identity", "delete", &name])?;
            let _ = run(
                "git",
                &["config", "--global", "--unset-all", "infinigit.identity"],
            );
            Ok(format!(
                "Removed InfiniGit identity '{name}' from this device."
            ))
        }
        AuthCommand::LinkDevice {
            name,
            label,
            storage,
            read_only,
            reuse_existing,
            directory,
            network,
            root_key,
        } => {
            let directory = directory.ok_or("a directory canister is required; pass --directory <canister-id>")?;
            let identities = run("icp", &["identity", "list", "-q"])?;
            let exists = identities.lines().any(|existing| existing == name);
            if exists && !reuse_existing {
                return Err(format!(
                    "identity '{name}' already exists; choose another --name, or add --reuse-existing only if a previous link-device attempt created it"
                ));
            }
            if !exists {
                run_interactive("icp", &["identity", "new", &name, "--storage", &storage])?;
            }
            let mut random = [0u8; 32];
            File::open("/dev/urandom")
                .and_then(|mut file| file.read_exact(&mut random))
                .map_err(|error| format!("cannot generate pairing code: {error}"))?;
            let digest = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let candid = format!("(\"{label}\", \"{digest}\", true, {}, null)", !read_only);
            let mut call = vec![
                "canister",
                "call",
                directory.as_str(),
                "request_device_link",
                candid.as_str(),
                "--identity",
                name.as_str(),
                "--network",
                network.as_str(),
            ];
            // Named networks such as `ic` already define their trust root, and
            // icp-cli rejects --root-key for them. Explicit replica URLs need
            // the flag so local development can fetch or pin a root key.
            if network.contains("://") {
                call.extend(["--root-key", root_key.as_str()]);
            }
            let response = run_with_prompt("icp", &call)?;
            let marker = "id = ";
            let id = response
                .find(marker)
                .and_then(|index| {
                    response[index + marker.len()..]
                        .split(|character: char| !character.is_ascii_digit())
                        .next()
                })
                .filter(|value| !value.is_empty())
                .ok_or("directory returned no device request id")?;
            configure(&name, None, None)?;
            let app = run(
                "git",
                &["config", "--global", "--get", "infinigit.app-origin"],
            )
            .unwrap_or_else(|_| DEFAULT_APP.into());
            Ok(format!(
                "Device identity created.\n\nOpen {app}/#/settings/devices and enter this pairing code:\n{id}:{digest}\n\nThe request expires in 15 minutes. Git will use '{name}' after approval."
            ))
        }
    }
}

fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match parse(&args).and_then(execute) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("infinigit: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_login_defaults_and_overrides() {
        assert_eq!(
            parse(&["auth".into(), "login".into()]).unwrap(),
            AuthCommand::Login {
                name: "infinigit".into(),
                auth: DEFAULT_AUTH.into(),
                app: DEFAULT_APP.into(),
                storage: "keyring".into(),
            }
        );
        assert_eq!(
            parse(&[
                "auth".into(),
                "login".into(),
                "--name".into(),
                "work".into(),
                "--app".into(),
                "https://code.example".into(),
                "--storage".into(),
                "password".into()
            ])
            .unwrap(),
            AuthCommand::Login {
                name: "work".into(),
                auth: DEFAULT_AUTH.into(),
                app: "https://code.example".into(),
                storage: "password".into(),
            }
        );
    }

    #[test]
    fn parses_lifecycle_commands_and_rejects_unsafe_values() {
        assert_eq!(
            parse(&["auth".into(), "status".into()]).unwrap(),
            AuthCommand::Status {
                name: DEFAULT_IDENTITY.into()
            }
        );
        assert_eq!(
            parse(&[
                "auth".into(),
                "reauth".into(),
                "--name".into(),
                "work_1".into()
            ])
            .unwrap(),
            AuthCommand::Reauth {
                name: "work_1".into()
            }
        );
        assert_eq!(
            parse(&["auth".into(), "logout".into()]).unwrap(),
            AuthCommand::Logout {
                name: DEFAULT_IDENTITY.into()
            }
        );
        assert!(
            parse(&[
                "auth".into(),
                "login".into(),
                "--name".into(),
                "../bad".into()
            ])
            .is_err()
        );
        assert!(
            parse(&[
                "auth".into(),
                "login".into(),
                "--auth".into(),
                "http://evil.example".into()
            ])
            .is_err()
        );
        assert!(
            parse(&[
                "auth".into(),
                "login".into(),
                "--storage".into(),
                "none".into()
            ])
            .is_err()
        );
        assert!(
            parse(&[
                "auth".into(),
                "link-device".into(),
                "--root-key".into(),
                "unsafe".into()
            ])
            .is_err()
        );
        assert!(parse(&["wrong".into()]).is_err());
    }

    #[test]
    fn parses_repository_import_and_rejects_non_infinigit_destinations() {
        assert_eq!(
            parse(&[
                "import".into(),
                "https://example.com/team/project.git".into(),
                "igit://infinigit.com/alice/project".into(),
            ])
            .unwrap(),
            AuthCommand::Import {
                source: "https://example.com/team/project.git".into(),
                destination: "igit://infinigit.com/alice/project".into(),
            }
        );
        assert!(
            parse(&[
                "import".into(),
                "--upload-pack=evil".into(),
                "igit://infinigit.com/alice/project".into()
            ])
            .is_err()
        );
        assert!(
            parse(&[
                "import".into(),
                "https://example.com/repo.git".into(),
                "https://example.com/other.git".into()
            ])
            .is_err()
        );
        assert!(
            parse(&[
                "import".into(),
                "source".into(),
                "igit://host/repo".into(),
                "extra".into()
            ])
            .is_err()
        );
    }
}

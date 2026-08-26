//! InfiniGit command-line authentication and configuration.

use std::{env, fs::File, io::Read, process::{Command, ExitCode}};

const DEFAULT_IDENTITY: &str = "infinigit";
const DEFAULT_AUTH: &str = "https://id.ai";
const DEFAULT_APP: &str = "https://infinigit.com";

#[derive(Debug, PartialEq, Eq)]
enum AuthCommand {
    Login { name: String, auth: String, app: String, storage: String },
    Status { name: String },
    Reauth { name: String },
    Logout { name: String },
    LinkDevice { name: String, label: String, storage: String, read_only: bool },
}

fn valid_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn value(args: &[String], flag: &str, fallback: &str) -> Result<String, String> {
    match args.iter().position(|arg| arg == flag) {
        Some(index) => args.get(index + 1).cloned().ok_or_else(|| format!("{flag} requires a value")),
        None => Ok(fallback.to_owned()),
    }
}

fn parse(args: &[String]) -> Result<AuthCommand, String> {
    if args.first().map(String::as_str) != Some("auth") {
        return Err("usage: infinigit auth <login|status|reauth|logout> [options]".into());
    }
    let action = args.get(1).map(String::as_str).ok_or("missing auth command")?;
    let name = value(args, "--name", DEFAULT_IDENTITY)?;
    if !valid_name(&name) { return Err("invalid identity name".into()); }
    match action {
        "login" => {
            let auth = value(args, "--auth", &env::var("INFINIGIT_AUTH_ORIGIN").unwrap_or_else(|_| DEFAULT_AUTH.into()))?;
            let app = value(args, "--app", &env::var("INFINIGIT_APP_ORIGIN").unwrap_or_else(|_| DEFAULT_APP.into()))?;
            let storage = value(args, "--storage", "password")?;
            if !matches!(storage.as_str(), "keyring" | "password" | "plaintext") { return Err("invalid identity storage".into()); }
            if !(auth.starts_with("https://") || auth.starts_with("http://localhost") || auth.starts_with("http://127.0.0.1")) { return Err("invalid auth origin".into()); }
            if !(app.starts_with("https://") || app.starts_with("http://localhost") || app.starts_with("http://127.0.0.1")) { return Err("invalid app origin".into()); }
            Ok(AuthCommand::Login { name, auth, app, storage })
        }
        "status" => Ok(AuthCommand::Status { name }),
        "reauth" => Ok(AuthCommand::Reauth { name }),
        "logout" => Ok(AuthCommand::Logout { name }),
        "link-device" => {
            let label = value(args, "--label", "CLI device")?;
            let storage = value(args, "--storage", "password")?;
            if label.is_empty() || label.len() > 80 || !label.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'-' | b'_' | b'.')) { return Err("invalid device label".into()); }
            if !matches!(storage.as_str(), "keyring" | "password" | "plaintext") { return Err("invalid identity storage".into()); }
            Ok(AuthCommand::LinkDevice { name, label, storage, read_only: args.iter().any(|arg| arg == "--read-only") })
        }
        _ => Err("usage: infinigit auth <login|status|reauth|logout> [options]".into()),
    }
}

fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program).args(args).output().map_err(|error| format!("cannot run {program}: {error}"))?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(if message.is_empty() { format!("{program} failed") } else { message });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn run_interactive(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program).args(args).status().map_err(|error| format!("cannot run {program}: {error}"))?;
    if status.success() { Ok(()) } else { Err(format!("{program} authentication failed")) }
}

fn configure(name: &str, auth: Option<&str>, app: Option<&str>) -> Result<(), String> {
    run("git", &["config", "--global", "infinigit.identity", name])?;
    if let Some(auth) = auth { run("git", &["config", "--global", "infinigit.auth-origin", auth])?; }
    if let Some(app) = app { run("git", &["config", "--global", "infinigit.app-origin", app])?; }
    Ok(())
}

fn execute(command: AuthCommand) -> Result<String, String> {
    match command {
        AuthCommand::Login { name, auth, app, storage } => {
            let identities = run("icp", &["identity", "list", "-q"])?;
            if identities.lines().any(|existing| existing == name) {
                return Err(format!("identity '{name}' already exists; use 'infinigit auth reauth --name {name}' or log out first"));
            }
            run_interactive("icp", &["identity", "link", "web", &name, "--auth", &auth, "--app", &app, "--storage", &storage])?;
            configure(&name, Some(&auth), Some(&app))?;
            let principal = run("icp", &["identity", "principal", "--identity", &name])?;
            Ok(format!("Signed in to InfiniGit as {principal}. Git will use the linked identity '{name}'."))
        }
        AuthCommand::Status { name } => {
            let principal = run("icp", &["identity", "principal", "--identity", &name])?;
            Ok(format!("InfiniGit identity: {name}\nPrincipal: {principal}"))
        }
        AuthCommand::Reauth { name } => {
            run_interactive("icp", &["identity", "reauth", &name])?;
            configure(&name, None, None)?;
            let principal = run("icp", &["identity", "principal", "--identity", &name])?;
            Ok(format!("InfiniGit delegation refreshed for {principal}."))
        }
        AuthCommand::Logout { name } => {
            let configured = run("git", &["config", "--global", "--get", "infinigit.identity"])?;
            if configured != name {
                return Err(format!("refusing to delete identity '{name}' because it is not the configured InfiniGit identity"));
            }
            run("icp", &["identity", "delete", &name])?;
            let _ = run("git", &["config", "--global", "--unset-all", "infinigit.identity"]);
            Ok(format!("Removed InfiniGit identity '{name}' from this device."))
        }
        AuthCommand::LinkDevice { name, label, storage, read_only } => {
            let identities = run("icp", &["identity", "list", "-q"])?;
            if identities.lines().any(|existing| existing == name) {
                return Err(format!("identity '{name}' already exists; choose another --name or log out first"));
            }
            run_interactive("icp", &["identity", "new", &name, "--storage", &storage])?;
            let directory = run("git", &["config", "--global", "--get", "infinigit.directory-canister"])?;
            let network = run("git", &["config", "--global", "--get", "infinigit.network"])?;
            let mut random = [0u8; 32];
            File::open("/dev/urandom").and_then(|mut file| file.read_exact(&mut random)).map_err(|error| format!("cannot generate pairing code: {error}"))?;
            let digest = random.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
            let candid = format!("(\"{label}\", \"{digest}\", true, {}, null)", !read_only);
            let response = run("icp", &["canister", "call", &directory, "request_device_link", &candid, "--identity", &name, "--network", &network])?;
            let marker = "id = ";
            let id = response.find(marker).and_then(|index| response[index + marker.len()..].split(|character: char| !character.is_ascii_digit()).next()).filter(|value| !value.is_empty()).ok_or("directory returned no device request id")?;
            configure(&name, None, None)?;
            let app = run("git", &["config", "--global", "--get", "infinigit.app-origin"]).unwrap_or_else(|_| DEFAULT_APP.into());
            Ok(format!("Device identity created.\n\nOpen {app}/#/settings/devices and enter this pairing code:\n{id}:{digest}\n\nThe request expires in 15 minutes. Git will use '{name}' after approval."))
        }
    }
}

fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match parse(&args).and_then(execute) {
        Ok(message) => { println!("{message}"); ExitCode::SUCCESS }
        Err(message) => { eprintln!("infinigit: {message}"); ExitCode::FAILURE }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_login_defaults_and_overrides() {
        assert_eq!(parse(&["auth".into(), "login".into()]).unwrap(), AuthCommand::Login {
            name: "infinigit".into(), auth: DEFAULT_AUTH.into(), app: DEFAULT_APP.into(), storage: "password".into(),
        });
        assert_eq!(parse(&["auth".into(), "login".into(), "--name".into(), "work".into(), "--app".into(), "https://code.example".into(), "--storage".into(), "password".into()]).unwrap(), AuthCommand::Login {
            name: "work".into(), auth: DEFAULT_AUTH.into(), app: "https://code.example".into(), storage: "password".into(),
        });
    }

    #[test]
    fn parses_lifecycle_commands_and_rejects_unsafe_values() {
        assert_eq!(parse(&["auth".into(), "status".into()]).unwrap(), AuthCommand::Status { name: DEFAULT_IDENTITY.into() });
        assert_eq!(parse(&["auth".into(), "reauth".into(), "--name".into(), "work_1".into()]).unwrap(), AuthCommand::Reauth { name: "work_1".into() });
        assert_eq!(parse(&["auth".into(), "logout".into()]).unwrap(), AuthCommand::Logout { name: DEFAULT_IDENTITY.into() });
        assert!(parse(&["auth".into(), "login".into(), "--name".into(), "../bad".into()]).is_err());
        assert!(parse(&["auth".into(), "login".into(), "--auth".into(), "http://evil.example".into()]).is_err());
        assert!(parse(&["auth".into(), "login".into(), "--storage".into(), "none".into()]).is_err());
        assert!(parse(&["wrong".into()]).is_err());
    }
}

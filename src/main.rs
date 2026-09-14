//! infinigit command-line authentication and configuration.

use candid::{CandidType, Decode, Encode, Principal};
use ic_vetkeys::{DerivedPublicKey, EncryptedVetKey, TransportSecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Deserialize;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    process::{Command, ExitCode, Stdio},
};

const DEFAULT_IDENTITY: &str = "infinigit";
const DEFAULT_AUTH: &str = "https://id.ai";
const DEFAULT_APP: &str = "https://infinigit.com";
const DEFAULT_NETWORK: &str = "ic";
const DEFAULT_DIRECTORY: &str = "vc3gg-2qaaa-aaaae-qklda-cai";

#[derive(Debug, PartialEq, Eq)]
enum AuthCommand {
    Secrets {
        args: Vec<String>,
    },
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
    if args.first().map(String::as_str) == Some("secrets") {
        if args.len() < 2 {
            return Err("usage: infinigit secrets <vaults|create|list|set|unset|put|pull|run|delete|access>".into());
        }
        return Ok(AuthCommand::Secrets {
            args: args[1..].to_vec(),
        });
    }
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
        return Err("usage: infinigit <auth|import|secrets> [options]".into());
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

#[derive(CandidType, Deserialize, Clone)]
struct VaultPermission {
    read: bool,
    write: bool,
    delete_secret: bool,
    delete_vault: bool,
    manage_permissions: bool,
}
#[derive(CandidType, Deserialize, Clone)]
struct VaultSecret {
    name: String,
    ciphertext: Vec<u8>,
}
#[derive(CandidType, Deserialize, Clone)]
struct VaultSummary {
    name: String,
    revision: u128,
    epoch: u128,
    secret_names: Vec<String>,
    permission: VaultPermission,
    updated_at: i128,
}
#[derive(CandidType, Deserialize, Clone)]
struct VaultSnapshot {
    name: String,
    revision: u128,
    epoch: u128,
    secrets: Vec<VaultSecret>,
    permission: VaultPermission,
    updated_at: i128,
}
#[allow(non_camel_case_types)]
#[derive(CandidType, Deserialize)]
enum VaultGrantSubject {
    user(Principal),
    team { organization: String, team: String },
}
#[derive(CandidType, Deserialize)]
struct VaultGrant {
    subject: VaultGrantSubject,
    permission: VaultPermission,
}
#[derive(CandidType, Deserialize)]
struct Route {
    namespace: String,
    name: String,
    storage_id: String,
    owner: Principal,
    shard: Principal,
}
#[derive(CandidType, Deserialize)]
struct Namespace {
    owner: Principal,
}
type CanisterResult<T> = std::result::Result<T, String>;

fn config(key: &str, fallback: &str) -> String {
    run("git", &["config", "--global", "--get", key]).unwrap_or_else(|_| fallback.into())
}

fn icp_call(canister: &str, method: &str, args: Vec<u8>, query: bool) -> Result<Vec<u8>, String> {
    let identity = config("infinigit.identity", DEFAULT_IDENTITY);
    let network = env::var("INFINIGIT_NETWORK")
        .unwrap_or_else(|_| config("infinigit.network", DEFAULT_NETWORK));
    let root_key =
        env::var("INFINIGIT_ROOT_KEY").unwrap_or_else(|_| config("infinigit.root-key", "mainnet"));
    let encoded = hex::encode(args);
    let mut owned = vec![
        "canister".to_string(),
        "call".into(),
        canister.into(),
        method.into(),
        encoded,
        "--args-format".into(),
        "hex".into(),
        "--output".into(),
        "hex".into(),
        "--identity".into(),
        identity,
        "--network".into(),
        network.clone(),
    ];
    if query {
        owned.push("--query".into())
    }
    if network.contains("://") {
        owned.extend(["--root-key".into(), root_key])
    }
    let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
    let response = run_with_prompt("icp", &refs)?;
    hex::decode(response.trim()).map_err(|_| "ICP returned an invalid Candid response".into())
}

fn repository_arg(args: &[String]) -> Result<(String, String), String> {
    let url = if let Some(index) = args.iter().position(|value| value == "--repo") {
        args.get(index + 1)
            .cloned()
            .ok_or("--repo requires an igit URL")?
    } else {
        run("git", &["remote", "get-url", "origin"]).map_err(|_| {
            "not in an infinigit checkout; pass --repo igit://host/namespace/repository"
        })?
    };
    let path = url
        .strip_prefix("igit://")
        .ok_or("repository must use an igit:// URL")?
        .split_once('/')
        .map(|(_, path)| path)
        .ok_or("invalid igit repository URL")?;
    let (namespace, name) = path
        .trim_end_matches('/')
        .split_once('/')
        .ok_or("invalid igit repository URL")?;
    if namespace.is_empty() || name.is_empty() || name.contains('/') {
        return Err("invalid igit repository URL".into());
    }
    Ok((namespace.into(), name.into()))
}

fn resolve_route(args: &[String]) -> Result<Route, String> {
    let (namespace, name) = repository_arg(args)?;
    let directory = env::var("INFINIGIT_DIRECTORY_CANISTER_ID")
        .unwrap_or_else(|_| config("infinigit.directory-canister", DEFAULT_DIRECTORY));
    let bytes = icp_call(
        &directory,
        "resolve_repository",
        Encode!(&namespace, &name).map_err(|e| e.to_string())?,
        true,
    )?;
    Decode!(&bytes, CanisterResult<Route>)
        .map_err(|e| e.to_string())?
        .map_err(|_| "repository not found".into())
}

fn list_vaults(route: &Route) -> Result<Vec<VaultSummary>, String> {
    let bytes = icp_call(
        &route.shard.to_text(),
        "list_vaults",
        Encode!(&route.owner, &route.storage_id).map_err(|e| e.to_string())?,
        true,
    )?;
    Decode!(&bytes, CanisterResult<Vec<VaultSummary>>).map_err(|e| e.to_string())?
}
fn get_vault(route: &Route, vault: &str) -> Result<VaultSnapshot, String> {
    let bytes = icp_call(
        &route.shard.to_text(),
        "get_vault",
        Encode!(&route.owner, &route.storage_id, &vault).map_err(|e| e.to_string())?,
        true,
    )?;
    Decode!(&bytes, CanisterResult<VaultSnapshot>).map_err(|e| e.to_string())?
}
fn vault_material(
    route: &Route,
    vault: &str,
    epoch: u128,
) -> Result<ic_vetkeys::DerivedKeyMaterial, String> {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let transport = TransportSecretKey::from_seed(seed.to_vec())?;
    let public_bytes = icp_call(
        &route.shard.to_text(),
        "vault_vetkey_public_key",
        Encode!().map_err(|e| e.to_string())?,
        false,
    )?;
    let public = Decode!(&public_bytes, CanisterResult<Vec<u8>>).map_err(|e| e.to_string())??;
    let encrypted_bytes = icp_call(
        &route.shard.to_text(),
        "vault_encrypted_key",
        Encode!(
            &route.owner,
            &route.storage_id,
            &vault,
            &epoch,
            &transport.public_key()
        )
        .map_err(|e| e.to_string())?,
        false,
    )?;
    let encrypted =
        Decode!(&encrypted_bytes, CanisterResult<Vec<u8>>).map_err(|e| e.to_string())??;
    let input = format!("{}/{}\0{}\0{}", route.owner, route.storage_id, vault, epoch);
    let key = EncryptedVetKey::deserialize(&encrypted)
        .map_err(|_| "invalid encrypted vault key")?
        .decrypt_and_verify(
            &transport,
            &DerivedPublicKey::deserialize(&public)
                .map_err(|_| "invalid vault verification key")?,
            input.as_bytes(),
        )?;
    Ok(key.as_derived_key_material())
}
fn secret_context(route: &Route, vault: &str, epoch: u128, name: &str) -> String {
    format!(
        "infinigit-secret-v1:{}/{}:{}:{}:{}",
        route.owner, route.storage_id, vault, epoch, name
    )
}
fn decrypt_vault(route: &Route, vault: &VaultSnapshot) -> Result<Vec<(String, String)>, String> {
    let material = vault_material(route, &vault.name, vault.epoch)?;
    vault
        .secrets
        .iter()
        .map(|secret| {
            let context = secret_context(route, &vault.name, vault.epoch, &secret.name);
            let value = material
                .decrypt_message(&secret.ciphertext, &context, context.as_bytes())
                .map_err(|_| format!("{} failed authentication", secret.name))?;
            Ok((
                secret.name.clone(),
                String::from_utf8(value).map_err(|_| format!("{} is not UTF-8", secret.name))?,
            ))
        })
        .collect()
}
fn encrypt_values(
    route: &Route,
    vault: &VaultSnapshot,
    values: &[(String, String)],
) -> Result<Vec<VaultSecret>, String> {
    let material = vault_material(route, &vault.name, vault.epoch)?;
    let mut rng = OsRng;
    values
        .iter()
        .map(|(name, value)| {
            let context = secret_context(route, &vault.name, vault.epoch, name);
            Ok(VaultSecret {
                name: name.clone(),
                ciphertext: material
                    .encrypt_message(value.as_bytes(), &context, context.as_bytes(), &mut rng)
                    .map_err(|_| "secret is too large")?,
            })
        })
        .collect()
}
fn update_secrets(
    route: &Route,
    vault: &VaultSnapshot,
    upserts: Vec<VaultSecret>,
    deletes: Vec<String>,
) -> Result<VaultSnapshot, String> {
    let bytes = icp_call(
        &route.shard.to_text(),
        "update_vault_secrets",
        Encode!(
            &route.owner,
            &route.storage_id,
            &vault.name,
            &upserts,
            &deletes,
            &vault.revision
        )
        .map_err(|e| e.to_string())?,
        false,
    )?;
    Decode!(&bytes, CanisterResult<VaultSnapshot>).map_err(|e| e.to_string())?
}
fn valid_secret_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_uppercase() || i > 0 && b.is_ascii_digit())
}
fn parse_dotenv(contents: &str) -> Result<Vec<(String, String)>, String> {
    let mut values = Vec::new();
    for (line_number, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (name, raw_value) = line
            .split_once('=')
            .ok_or_else(|| format!("invalid dotenv line {}", line_number + 1))?;
        let name = name.trim();
        if !valid_secret_name(name) || values.iter().any(|(existing, _)| existing == name) {
            return Err(format!("invalid or duplicate secret key {name}"));
        }
        let value = raw_value.trim();
        let value = if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            value[1..value.len() - 1].to_string()
        } else {
            value.to_string()
        };
        values.push((name.into(), value));
    }
    Ok(values)
}
fn dotenv_quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    )
}
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
fn requested_permission(args: &[String]) -> Result<VaultPermission, String> {
    let mut permission = VaultPermission {
        read: args.iter().any(|a| a == "--read"),
        write: args.iter().any(|a| a == "--write"),
        delete_secret: args.iter().any(|a| a == "--delete-secrets"),
        delete_vault: args.iter().any(|a| a == "--delete-vault"),
        manage_permissions: args.iter().any(|a| a == "--manage-access"),
    };
    if permission.write
        || permission.delete_secret
        || permission.delete_vault
        || permission.manage_permissions
    {
        permission.read = true
    }
    if permission.manage_permissions {
        permission.write = true
    }
    if !permission.read {
        return Err("select at least one permission: --read, --write, --delete-secrets, --delete-vault, or --manage-access".into());
    }
    Ok(permission)
}
fn permission_labels(permission: &VaultPermission) -> String {
    [
        (permission.read, "read"),
        (permission.write, "write"),
        (permission.delete_secret, "delete-secrets"),
        (permission.delete_vault, "delete-vault"),
        (permission.manage_permissions, "manage-access"),
    ]
    .into_iter()
    .filter_map(|(enabled, name)| enabled.then_some(name))
    .collect::<Vec<_>>()
    .join(",")
}
fn execute_access(route: &Route, args: &[String]) -> Result<String, String> {
    let action = args.get(1).map(String::as_str).ok_or("usage: infinigit secrets access <list|grant-user|revoke-user|grant-team|revoke-team> <vault>")?;
    let vault = args.get(2).ok_or("vault name is required")?;
    let directory = env::var("INFINIGIT_DIRECTORY_CANISTER_ID")
        .unwrap_or_else(|_| config("infinigit.directory-canister", DEFAULT_DIRECTORY));
    match action {
        "list" => { let bytes = icp_call(&route.shard.to_text(), "list_vault_grants", Encode!(&route.owner, &route.storage_id, vault).map_err(|e| e.to_string())?, true)?; let grants = Decode!(&bytes, CanisterResult<Vec<VaultGrant>>).map_err(|e| e.to_string())??; Ok(grants.into_iter().map(|grant| format!("{}\t{}", match grant.subject { VaultGrantSubject::user(user) => user.to_text(), VaultGrantSubject::team { organization, team } => format!("{organization}/{team}") }, permission_labels(&grant.permission))).collect::<Vec<_>>().join("\n")) },
        "grant-user" => { let username = args.get(3).ok_or("username is required")?; let resolved = icp_call(&directory, "resolve_namespace", Encode!(username).map_err(|e| e.to_string())?, true)?; let user = Decode!(&resolved, CanisterResult<Namespace>).map_err(|e| e.to_string())??.owner; let permission = requested_permission(args)?; let bytes = icp_call(&route.shard.to_text(), "set_vault_user_grant", Encode!(&route.owner, &route.storage_id, vault, &user, &permission).map_err(|e| e.to_string())?, false)?; Decode!(&bytes, CanisterResult<()>).map_err(|e| e.to_string())??; Ok(format!("Saved {vault} access for {username}.")) },
        "revoke-user" => { let username = args.get(3).ok_or("username is required")?; let resolved = icp_call(&directory, "resolve_namespace", Encode!(username).map_err(|e| e.to_string())?, true)?; let user = Decode!(&resolved, CanisterResult<Namespace>).map_err(|e| e.to_string())??.owner; let bytes = icp_call(&route.shard.to_text(), "revoke_vault_user_grant", Encode!(&route.owner, &route.storage_id, vault, &user).map_err(|e| e.to_string())?, false)?; Decode!(&bytes, CanisterResult<()>).map_err(|e| e.to_string())??; Ok(format!("Revoked {vault} access from {username}.")) },
        "grant-team" => { let organization = args.get(3).ok_or("organization is required")?; let team = args.get(4).ok_or("team is required")?; let permission = requested_permission(args)?; let bytes = icp_call(&directory, "grant_vault_team", Encode!(&organization, &team, &route.namespace, &route.name, vault, &permission).map_err(|e| e.to_string())?, false)?; Decode!(&bytes, CanisterResult<()>).map_err(|e| e.to_string())??; Ok(format!("Saved {vault} access for {organization}/{team}.")) },
        "revoke-team" => { let organization = args.get(3).ok_or("organization is required")?; let team = args.get(4).ok_or("team is required")?; let bytes = icp_call(&directory, "revoke_vault_team", Encode!(&organization, &team, &route.namespace, &route.name, vault).map_err(|e| e.to_string())?, false)?; Decode!(&bytes, CanisterResult<()>).map_err(|e| e.to_string())??; Ok(format!("Revoked {vault} access from {organization}/{team}.")) },
        _ => Err("usage: infinigit secrets access <list|grant-user|revoke-user|grant-team|revoke-team> <vault>".into()),
    }
}

fn execute_secrets(args: Vec<String>) -> Result<String, String> {
    let action = args
        .first()
        .map(String::as_str)
        .ok_or("missing secrets command")?;
    let route = resolve_route(&args)?;
    match action {
        "access" => execute_access(&route, &args),
        "vaults" => Ok(list_vaults(&route)?
            .into_iter()
            .map(|v| {
                format!(
                    "{}\t{} secrets\trevision {}",
                    v.name,
                    v.secret_names.len(),
                    v.revision
                )
            })
            .collect::<Vec<_>>()
            .join("\n")),
        "create" => {
            let vault = args
                .get(1)
                .ok_or("usage: infinigit secrets create <vault>")?;
            let bytes = icp_call(
                &route.shard.to_text(),
                "create_vault",
                Encode!(&route.owner, &route.storage_id, vault).map_err(|e| e.to_string())?,
                false,
            )?;
            let created =
                Decode!(&bytes, CanisterResult<VaultSummary>).map_err(|e| e.to_string())??;
            Ok(format!("Created vault '{}'.", created.name))
        }
        "list" => {
            let vault = args.get(1).ok_or("usage: infinigit secrets list <vault>")?;
            Ok(get_vault(&route, vault)?
                .secrets
                .into_iter()
                .map(|s| s.name)
                .collect::<Vec<_>>()
                .join("\n"))
        }
        "set" => {
            let vault_name = args
                .get(1)
                .ok_or("usage: infinigit secrets set <vault> <KEY> [--stdin]")?;
            let name = args
                .get(2)
                .ok_or("usage: infinigit secrets set <vault> <KEY> [--stdin]")?;
            if !valid_secret_name(name) {
                return Err(
                    "secret keys must use uppercase letters, digits, and underscores".into(),
                );
            }
            let mut value = String::new();
            if args.iter().any(|a| a == "--stdin") {
                io::stdin()
                    .read_to_string(&mut value)
                    .map_err(|e| e.to_string())?;
                if value.ends_with('\n') {
                    value.pop();
                    if value.ends_with('\r') {
                        value.pop();
                    }
                }
            } else {
                value = rpassword::prompt_password(format!("Value for {name}: "))
                    .map_err(|e| e.to_string())?
            }
            let vault = get_vault(&route, vault_name)?;
            let encrypted = encrypt_values(&route, &vault, &[(name.clone(), value)])?;
            let updated = update_secrets(&route, &vault, encrypted, vec![])?;
            Ok(format!(
                "Saved {name} in {} at revision {}.",
                vault.name, updated.revision
            ))
        }
        "unset" => {
            let vault_name = args
                .get(1)
                .ok_or("usage: infinigit secrets unset <vault> <KEY>")?;
            let name = args
                .get(2)
                .ok_or("usage: infinigit secrets unset <vault> <KEY>")?;
            let vault = get_vault(&route, vault_name)?;
            let updated = update_secrets(&route, &vault, vec![], vec![name.clone()])?;
            Ok(format!(
                "Deleted {name} from {} at revision {}.",
                vault.name, updated.revision
            ))
        }
        "put" => {
            let vault_name = args
                .get(1)
                .ok_or("usage: infinigit secrets put <vault> --from-dotenv <file>")?;
            let index = args
                .iter()
                .position(|a| a == "--from-dotenv")
                .ok_or("--from-dotenv <file> is required")?;
            let path = args.get(index + 1).ok_or("--from-dotenv requires a file")?;
            let values = parse_dotenv(
                &fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?,
            )?;
            let vault = get_vault(&route, vault_name)?;
            let deletes = vault
                .secrets
                .iter()
                .filter(|s| !values.iter().any(|(name, _)| name == &s.name))
                .map(|s| s.name.clone())
                .collect();
            let count = values.len();
            let encrypted = encrypt_values(&route, &vault, &values)?;
            let updated = update_secrets(&route, &vault, encrypted, deletes)?;
            Ok(format!(
                "Published {count} secrets to {} at revision {}.",
                vault.name, updated.revision
            ))
        }
        "pull" => {
            let vault_name = args.get(1).ok_or(
                "usage: infinigit secrets pull <vault> --format <dotenv|shell> [--output file]",
            )?;
            let vault = get_vault(&route, vault_name)?;
            let values = decrypt_vault(&route, &vault)?;
            let format = value(&args, "--format", "dotenv")?;
            let content = match format.as_str() {
                "dotenv" => {
                    values
                        .iter()
                        .map(|(k, v)| format!("{k}={}", dotenv_quote(v)))
                        .collect::<Vec<_>>()
                        .join("\n")
                        + "\n"
                }
                "shell" => {
                    values
                        .iter()
                        .map(|(k, v)| format!("export {k}={}", shell_quote(v)))
                        .collect::<Vec<_>>()
                        .join("\n")
                        + "\n"
                }
                _ => return Err("--format must be dotenv or shell".into()),
            };
            if let Some(index) = args.iter().position(|a| a == "--output") {
                let path = args.get(index + 1).ok_or("--output requires a file")?;
                let mut options = OpenOptions::new();
                options
                    .write(true)
                    .create_new(!args.iter().any(|a| a == "--force"))
                    .create(args.iter().any(|a| a == "--force"))
                    .truncate(args.iter().any(|a| a == "--force"));
                #[cfg(unix)]
                options.mode(0o600);
                options
                    .open(path)
                    .and_then(|mut file| file.write_all(content.as_bytes()))
                    .map_err(|e| format!("cannot write {path}: {e}"))?;
                Ok(format!("Wrote {} secrets to {path}.", values.len()))
            } else {
                Ok(content.trim_end().into())
            }
        }
        "run" => {
            let vault_name = args
                .get(1)
                .ok_or("usage: infinigit secrets run <vault> -- <command>")?;
            let separator = args
                .iter()
                .position(|a| a == "--")
                .ok_or("separate the command with --")?;
            let program = args.get(separator + 1).ok_or("missing command")?;
            let values = decrypt_vault(&route, &get_vault(&route, vault_name)?)?;
            let status = Command::new(program)
                .args(&args[separator + 2..])
                .envs(values)
                .status()
                .map_err(|e| format!("cannot run {program}: {e}"))?;
            if status.success() {
                Ok(String::new())
            } else {
                Err(format!("command exited with {status}"))
            }
        }
        "rotate" => {
            let vault_name = args
                .get(1)
                .ok_or("usage: infinigit secrets rotate <vault>")?;
            let vault = get_vault(&route, vault_name)?;
            let values = decrypt_vault(&route, &vault)?;
            let mut random = [0u8; 16];
            OsRng.fill_bytes(&mut random);
            let mut new_epoch = u128::from_be_bytes(random);
            if new_epoch == 0 || new_epoch == vault.epoch {
                new_epoch = new_epoch.wrapping_add(1)
            }
            let next = VaultSnapshot {
                epoch: new_epoch,
                ..vault.clone()
            };
            let replacements = encrypt_values(&route, &next, &values)?;
            let bytes = icp_call(
                &route.shard.to_text(),
                "rotate_vault",
                Encode!(
                    &route.owner,
                    &route.storage_id,
                    vault_name,
                    &new_epoch,
                    &replacements,
                    &vault.revision
                )
                .map_err(|e| e.to_string())?,
                false,
            )?;
            let updated =
                Decode!(&bytes, CanisterResult<VaultSnapshot>).map_err(|e| e.to_string())??;
            Ok(format!(
                "Rotated vault '{}' to revision {}.",
                updated.name, updated.revision
            ))
        }
        "delete" => {
            let vault_name = args
                .get(1)
                .ok_or("usage: infinigit secrets delete <vault> --yes")?;
            if !args.iter().any(|a| a == "--yes") {
                return Err("refusing to delete a vault without --yes".into());
            }
            let vault = get_vault(&route, vault_name)?;
            let bytes = icp_call(
                &route.shard.to_text(),
                "delete_vault",
                Encode!(&route.owner, &route.storage_id, vault_name, &vault.revision)
                    .map_err(|e| e.to_string())?,
                false,
            )?;
            Decode!(&bytes, CanisterResult<()>).map_err(|e| e.to_string())??;
            Ok(format!("Deleted vault '{vault_name}'."))
        }
        _ => Err(
            "usage: infinigit secrets <vaults|create|list|set|unset|put|pull|run|delete|access>"
                .into(),
        ),
    }
}

fn execute(command: AuthCommand) -> Result<String, String> {
    match command {
        AuthCommand::Secrets { args } => execute_secrets(args),
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
            .map_err(|error| format!("infinigit push failed: {error}"))?;
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
                "Signed in to infinigit as {principal}. Git will use the linked identity '{name}'."
            ))
        }
        AuthCommand::Status { name } => {
            let principal = run("icp", &["identity", "principal", "--identity", &name])?;
            Ok(format!(
                "infinigit identity: {name}\nPrincipal: {principal}"
            ))
        }
        AuthCommand::Reauth { name } => {
            run_interactive("icp", &["identity", "reauth", &name])?;
            configure(&name, None, None)?;
            let principal = run("icp", &["identity", "principal", "--identity", &name])?;
            Ok(format!("infinigit delegation refreshed for {principal}."))
        }
        AuthCommand::Logout { name } => {
            let configured = run(
                "git",
                &["config", "--global", "--get", "infinigit.identity"],
            )?;
            if configured != name {
                return Err(format!(
                    "refusing to delete identity '{name}' because it is not the configured infinigit identity"
                ));
            }
            run("icp", &["identity", "delete", &name])?;
            let _ = run(
                "git",
                &["config", "--global", "--unset-all", "infinigit.identity"],
            );
            Ok(format!(
                "Removed infinigit identity '{name}' from this device."
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
            let directory = directory
                .ok_or("a directory canister is required; pass --directory <canister-id>")?;
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
        assert!(parse(&[
            "auth".into(),
            "login".into(),
            "--name".into(),
            "../bad".into()
        ])
        .is_err());
        assert!(parse(&[
            "auth".into(),
            "login".into(),
            "--auth".into(),
            "http://evil.example".into()
        ])
        .is_err());
        assert!(parse(&[
            "auth".into(),
            "login".into(),
            "--storage".into(),
            "none".into()
        ])
        .is_err());
        assert!(parse(&[
            "auth".into(),
            "link-device".into(),
            "--root-key".into(),
            "unsafe".into()
        ])
        .is_err());
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
        assert!(parse(&[
            "import".into(),
            "--upload-pack=evil".into(),
            "igit://infinigit.com/alice/project".into()
        ])
        .is_err());
        assert!(parse(&[
            "import".into(),
            "https://example.com/repo.git".into(),
            "https://example.com/other.git".into()
        ])
        .is_err());
        assert!(parse(&[
            "import".into(),
            "source".into(),
            "igit://host/repo".into(),
            "extra".into()
        ])
        .is_err());
    }

    #[test]
    fn parses_secrets_commands_without_interpreting_secret_values() {
        assert_eq!(
            parse(&[
                "secrets".into(),
                "pull".into(),
                "prod".into(),
                "--format".into(),
                "shell".into()
            ])
            .unwrap(),
            AuthCommand::Secrets {
                args: vec![
                    "pull".into(),
                    "prod".into(),
                    "--format".into(),
                    "shell".into()
                ]
            }
        );
        assert!(parse(&["secrets".into()]).is_err());
    }

    #[test]
    fn validates_and_quotes_environment_values() {
        assert!(valid_secret_name("DATABASE_URL"));
        assert!(valid_secret_name("_TOKEN_2"));
        assert!(!valid_secret_name("2_TOKEN"));
        assert!(!valid_secret_name("mixedCase"));
        assert_eq!(dotenv_quote("a\"b\n"), "\"a\\\"b\\n\"");
        assert_eq!(shell_quote("it's safe"), "'it'\\''s safe'");
    }

    #[test]
    fn parses_dotenv_and_rejects_ambiguous_input() {
        assert_eq!(
            parse_dotenv("# deployment\nexport API_TOKEN='abc'\nEMPTY=\"\"\n").unwrap(),
            vec![
                ("API_TOKEN".into(), "abc".into()),
                ("EMPTY".into(), "".into())
            ]
        );
        assert!(parse_dotenv("bad=value").is_err());
        assert!(parse_dotenv("TOKEN=one\nTOKEN=two").is_err());
        assert!(parse_dotenv("not-an-assignment").is_err());
    }

    #[test]
    fn permission_flags_apply_required_implications() {
        let permission = requested_permission(&["--manage-access".into()]).unwrap();
        assert!(permission.read && permission.write && permission.manage_permissions);
        assert!(requested_permission(&[]).is_err());
    }
}

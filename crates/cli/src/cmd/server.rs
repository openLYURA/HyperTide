use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub(crate) struct ServerArgs {
    #[command(subcommand)]
    pub command: ServerCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ServerCommand {
    #[command(about = "Validate production server configuration and readiness")]
    Doctor(ServerDoctorArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ServerDoctorArgs {
    #[arg(long, default_value = "deploy/server/.env.production")]
    pub env_file: String,
    #[arg(long, help = "Optional server URL to check /health/ready and /metrics")]
    pub server_url: Option<String>,
}

pub(crate) async fn execute(args: ServerArgs) -> Result<()> {
    match args.command {
        ServerCommand::Doctor(args) => doctor(args).await,
    }
}

async fn doctor(args: ServerDoctorArgs) -> Result<()> {
    let env = read_env_file(&args.env_file)?;
    let report = validate_server_env(&env);
    for line in &report.lines {
        println!("{line}");
    }

    let mut errors = report.errors;
    if let Some(server_url) = args.server_url {
        errors += check_remote_server(&server_url).await?;
    }

    if errors > 0 {
        return Err(anyhow!("server doctor found {errors} error(s)"));
    }
    Ok(())
}

fn read_env_file(path: &str) -> Result<HashMap<String, String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read server env file: {path}"))?;
    Ok(parse_env_text(&text))
}

fn parse_env_text(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            let (name, value) = trimmed.split_once('=')?;
            Some((
                name.trim().to_string(),
                value.trim().trim_matches('"').to_string(),
            ))
        })
        .collect()
}

struct DoctorReport {
    lines: Vec<String>,
    errors: usize,
}

fn validate_server_env(env: &HashMap<String, String>) -> DoctorReport {
    let mut lines = Vec::new();
    let mut errors = 0;

    for required in [
        "APP_ENV",
        "DATABASE_URL",
        "MASTER_KEY",
        "AUTH_PEPPER",
        "JWT_PRIVATE_KEY_PATH",
        "JWT_PUBLIC_KEY_PATH",
        "HIGH_RISK_SIGNATURE_REQUIRED",
        "HIGH_RISK_SIGNING_SECRET",
        "CORS_ALLOWED_ORIGINS",
        "RATE_LIMIT_REQUESTS_PER_MINUTE",
        "TRUSTED_PROXY_CIDRS",
        "STORAGE_PATH",
    ] {
        match env.get(required).filter(|value| !value.trim().is_empty()) {
            Some(value) if !value.contains("CHANGE_ME") => {
                lines.push(format!("[ok]   {required}: set"));
            }
            Some(_) => {
                lines.push(format!("[err]  {required}: placeholder value"));
                errors += 1;
            }
            None => {
                lines.push(format!("[err]  {required}: missing"));
                errors += 1;
            }
        }
    }

    if env
        .get("APP_ENV")
        .is_some_and(|value| value != "production")
    {
        lines.push("[err]  APP_ENV: must be production".to_string());
        errors += 1;
    }
    if env
        .get("HIGH_RISK_SIGNATURE_REQUIRED")
        .is_some_and(|value| value != "true")
    {
        lines.push("[err]  HIGH_RISK_SIGNATURE_REQUIRED: must be true".to_string());
        errors += 1;
    }
    if env
        .get("MASTER_KEY")
        .is_some_and(|value| value == "dev-master-key")
    {
        lines.push("[err]  MASTER_KEY: development secret is not allowed".to_string());
        errors += 1;
    }
    if env
        .get("AUTH_PEPPER")
        .is_some_and(|value| value.contains("dev-pepper"))
    {
        lines.push("[err]  AUTH_PEPPER: development pepper is not allowed".to_string());
        errors += 1;
    }

    if !env.contains_key("WITNESS_CONFIG_JSON") && !env.contains_key("WITNESS_CONFIG_FILE") {
        lines.push(
            "[err]  witness: WITNESS_CONFIG_JSON or WITNESS_CONFIG_FILE is required".to_string(),
        );
        errors += 1;
    } else {
        lines.push("[ok]   witness: configuration source set".to_string());
    }

    for key_name in [
        "JWT_PRIVATE_KEY_PATH",
        "JWT_PUBLIC_KEY_PATH",
        "WITNESS_CONFIG_FILE",
    ] {
        if let Some(path) = env.get(key_name).filter(|path| !path.trim().is_empty()) {
            if Path::new(path).is_file() {
                lines.push(format!("[ok]   {key_name}: file exists"));
            } else {
                lines.push(format!(
                    "[warn] {key_name}: file not found from current directory"
                ));
            }
        }
    }

    DoctorReport { lines, errors }
}

async fn check_remote_server(server_url: &str) -> Result<usize> {
    let client = reqwest::Client::new();
    let base = server_url.trim_end_matches('/');
    let mut errors = 0;

    for path in ["/health/ready", "/metrics"] {
        let url = format!("{base}{path}");
        match client
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                println!("[ok]   remote {path}: HTTP {}", response.status());
            }
            Ok(response) => {
                println!("[err]  remote {path}: HTTP {}", response.status());
                errors += 1;
            }
            Err(error) => {
                println!("[err]  remote {path}: {error}");
                errors += 1;
            }
        }
    }

    Ok(errors)
}

#[cfg(test)]
mod tests {
    use super::{parse_env_text, validate_server_env};

    #[test]
    fn server_env_doctor_rejects_placeholders_and_missing_witness() {
        let env = parse_env_text(
            r#"
APP_ENV=production
DATABASE_URL=postgres://hypertide:secret@postgres:5432/hypertide
MASTER_KEY=CHANGE_ME_MASTER
AUTH_PEPPER=secure-pepper
JWT_PRIVATE_KEY_PATH=Cargo.toml
JWT_PUBLIC_KEY_PATH=Cargo.toml
HIGH_RISK_SIGNATURE_REQUIRED=true
HIGH_RISK_SIGNING_SECRET=secure-secret
CORS_ALLOWED_ORIGINS=https://hypertide.example.com
RATE_LIMIT_REQUESTS_PER_MINUTE=600
TRUSTED_PROXY_CIDRS=172.16.0.0/12
STORAGE_PATH=/app/storage
"#,
        );

        let report = validate_server_env(&env);
        assert!(report.errors >= 2);
        assert!(report.lines.iter().any(|line| line.contains("MASTER_KEY")));
        assert!(report.lines.iter().any(|line| line.contains("witness")));
    }
}

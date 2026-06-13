use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::utils::*;

#[derive(Debug, Args)]
pub(crate) struct DoctorArgs {}

#[derive(Serialize)]
struct DoctorCheck {
    name: String,
    status: String,
    message: String,
}

pub(crate) async fn execute(_args: DoctorArgs) -> Result<()> {
    let mut checks: Vec<DoctorCheck> = Vec::new();
    let mut ok_count = 0u32;
    let mut warn_count = 0u32;
    let mut err_count = 0u32;

    // 1. Login state
    match load_profile() {
        Ok(profile) => {
            let mode = if profile.api_key_direct {
                "api-key-direct"
            } else {
                "jwt"
            };
            let msg = format!("server={}, mode={}", profile.server, mode);
            if !json_output_enabled() {
                println!("[ok]   login: {}", msg);
            }
            checks.push(DoctorCheck {
                name: "login".to_string(),
                status: "ok".to_string(),
                message: msg,
            });
            ok_count += 1;

            // 2. Server connectivity
            let client = reqwest::Client::new();
            let health_url = format!("{}/health/ready", profile.server.trim_end_matches('/'));
            match client
                .get(&health_url)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    let msg = format!("{} responding", profile.server);
                    if !json_output_enabled() {
                        println!("[ok]   server: {}", msg);
                    }
                    checks.push(DoctorCheck {
                        name: "server".to_string(),
                        status: "ok".to_string(),
                        message: msg,
                    });
                    ok_count += 1;
                }
                Ok(resp) => {
                    let msg = format!("{} returned HTTP {}", profile.server, resp.status());
                    if !json_output_enabled() {
                        println!("[warn] server: {}", msg);
                    }
                    checks.push(DoctorCheck {
                        name: "server".to_string(),
                        status: "warn".to_string(),
                        message: msg,
                    });
                    warn_count += 1;
                }
                Err(e) => {
                    let msg = format!("{} unreachable ({})", profile.server, e);
                    if !json_output_enabled() {
                        println!("[err]  server: {}", msg);
                    }
                    checks.push(DoctorCheck {
                        name: "server".to_string(),
                        status: "err".to_string(),
                        message: msg,
                    });
                    err_count += 1;
                }
            }

            // 3. Default repo
            match &profile.current_repo {
                Some(repo) => {
                    if !json_output_enabled() {
                        println!("[ok]   default repo: {}", repo);
                    }
                    checks.push(DoctorCheck {
                        name: "default repo".to_string(),
                        status: "ok".to_string(),
                        message: repo.clone(),
                    });
                    ok_count += 1;
                }
                None => {
                    let msg = "not set (use --repo or re-login)".to_string();
                    if !json_output_enabled() {
                        println!("[warn] default repo: {}", msg);
                    }
                    checks.push(DoctorCheck {
                        name: "default repo".to_string(),
                        status: "warn".to_string(),
                        message: msg,
                    });
                    warn_count += 1;
                }
            }

            // 4. Default branch
            if !json_output_enabled() {
                println!("[ok]   default branch: {}", profile.current_branch);
            }
            checks.push(DoctorCheck {
                name: "default branch".to_string(),
                status: "ok".to_string(),
                message: profile.current_branch.clone(),
            });
            ok_count += 1;

            // 5. Token expiry
            if !profile.api_key_direct {
                if token_expired(&profile) {
                    let msg = "expired — run 'ht login' to refresh".to_string();
                    if !json_output_enabled() {
                        println!("[warn] token: {}", msg);
                    }
                    checks.push(DoctorCheck {
                        name: "token".to_string(),
                        status: "warn".to_string(),
                        message: msg,
                    });
                    warn_count += 1;
                } else if let Some(expires_at) = profile.access_token_expires_at {
                    let remaining = expires_at - now_unix();
                    if remaining < 300 {
                        let msg = format!(
                            "expires in {}s — consider 'ht login' to refresh",
                            remaining
                        );
                        if !json_output_enabled() {
                            println!("[warn] token: {}", msg);
                        }
                        checks.push(DoctorCheck {
                            name: "token".to_string(),
                            status: "warn".to_string(),
                            message: msg,
                        });
                        warn_count += 1;
                    } else {
                        let msg = format!("valid ({}s remaining)", remaining);
                        if !json_output_enabled() {
                            println!("[ok]   token: {}", msg);
                        }
                        checks.push(DoctorCheck {
                            name: "token".to_string(),
                            status: "ok".to_string(),
                            message: msg,
                        });
                        ok_count += 1;
                    }
                }
            }
        }
        Err(_) => {
            let msg = "not configured — run 'ht login --server <url> --token <key>'".to_string();
            if !json_output_enabled() {
                println!("[err]  login: {}", msg);
            }
            checks.push(DoctorCheck {
                name: "login".to_string(),
                status: "err".to_string(),
                message: msg,
            });
            err_count += 1;
        }
    }

    // 6. Workspace state
    match load_workspace() {
        Ok(workspace) => {
            let msg = format!(
                "{} assets checked out (branch={})",
                workspace.checked_out_assets.len(),
                workspace.branch
            );
            if !json_output_enabled() {
                println!("[ok]   workspace: {}", msg);
            }
            checks.push(DoctorCheck {
                name: "workspace".to_string(),
                status: "ok".to_string(),
                message: msg,
            });
            ok_count += 1;
        }
        Err(_) => {
            let msg = "not initialized — run 'ht checkout'".to_string();
            if !json_output_enabled() {
                println!("[warn] workspace: {}", msg);
            }
            checks.push(DoctorCheck {
                name: "workspace".to_string(),
                status: "warn".to_string(),
                message: msg,
            });
            warn_count += 1;
        }
    }

    // 7. Stage state
    match load_stage() {
        Ok(stage) => {
            if stage.assets.is_empty() {
                if !json_output_enabled() {
                    println!("[ok]   stage: empty");
                }
                checks.push(DoctorCheck {
                    name: "stage".to_string(),
                    status: "ok".to_string(),
                    message: "empty".to_string(),
                });
            } else {
                let msg = format!(
                    "{} asset(s) pending — run 'ht submit' or 'ht stage clear'",
                    stage.assets.len()
                );
                if !json_output_enabled() {
                    println!("[warn] stage: {}", msg);
                }
                checks.push(DoctorCheck {
                    name: "stage".to_string(),
                    status: "warn".to_string(),
                    message: msg,
                });
                warn_count += 1;
            }
            ok_count += 1;
        }
        Err(_) => {
            let msg = "not initialized (will be created on first 'ht add')".to_string();
            if !json_output_enabled() {
                println!("[ok]   stage: {}", msg);
            }
            checks.push(DoctorCheck {
                name: "stage".to_string(),
                status: "ok".to_string(),
                message: msg,
            });
            ok_count += 1;
        }
    }

    // 输出结果
    if json_output_enabled() {
        let ok = err_count == 0;
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "ok": ok,
            "checks": checks,
            "ok_count": ok_count,
            "warn_count": warn_count,
            "err_count": err_count,
        }))?);
    } else {
        println!();
        println!(
            "doctor: {} ok, {} warning(s), {} error(s)",
            ok_count, warn_count, err_count
        );
    }
    if err_count > 0 {
        std::process::exit(1);
    }
    Ok(())
}

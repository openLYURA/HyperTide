use axum::http::HeaderValue;
use ipnet::IpNet;
use std::path::Path;

const DEV_MASTER_KEY: &str = "dev-master-key";
const DEV_HIGH_RISK_SIGNING_SECRET: &str = "hypertide-dev-signing-secret";
const DEV_AUTH_PEPPER: &str = "hypertide-dev-pepper";
const DEFAULT_RATE_LIMIT_REQUESTS_PER_MINUTE: u64 = 600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEnv {
    Development,
    Production,
}

impl AppEnv {
    pub fn from_str(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "development" | "dev" => Ok(Self::Development),
            "production" | "prod" => Ok(Self::Production),
            _ => Err(format!(
                "invalid APP_ENV: {value} (expected development|production)"
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Production => "production",
        }
    }

    pub fn is_production(&self) -> bool {
        matches!(self, Self::Production)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Plain,
    Json,
}

impl LogFormat {
    fn from_str(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "plain" | "text" => Ok(Self::Plain),
            "json" => Ok(Self::Json),
            _ => Err(format!("invalid LOG_FORMAT: {value} (expected plain|json)")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Json => "json",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub app_env: AppEnv,
    pub master_key: String,
    pub storage_path: String,
    pub cors_allowed_origins: Vec<HeaderValue>,
    pub rate_limit_requests_per_minute: u64,
    pub trusted_proxy_cidrs: Vec<IpNet>,
    pub log_format: LogFormat,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    fn from_lookup<F>(lookup: F) -> Result<Self, String>
    where
        F: Fn(&str) -> Option<String>,
    {
        let app_env = match lookup("APP_ENV") {
            Some(value) => AppEnv::from_str(&value)?,
            None => AppEnv::Development,
        };

        let master_key = match lookup("MASTER_KEY").map(|value| value.trim().to_string()) {
            Some(value) if !value.is_empty() => value,
            _ if app_env.is_production() => {
                return Err("MASTER_KEY is required when APP_ENV=production".to_string());
            }
            _ => DEV_MASTER_KEY.to_string(),
        };
        if app_env.is_production() && master_key == DEV_MASTER_KEY {
            return Err("MASTER_KEY must not use development default in production".to_string());
        }

        let storage_path = lookup("STORAGE_PATH")
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "./storage".to_string());

        let cors_allowed_origins = parse_origin_list(lookup("CORS_ALLOWED_ORIGINS").as_deref())?;
        if app_env.is_production() && cors_allowed_origins.is_empty() {
            return Err("CORS_ALLOWED_ORIGINS is required when APP_ENV=production".to_string());
        }

        if app_env.is_production() {
            enforce_production_security_gate(&lookup)?;
        }

        let rate_limit_requests_per_minute = parse_u64(
            lookup("RATE_LIMIT_REQUESTS_PER_MINUTE").as_deref(),
            DEFAULT_RATE_LIMIT_REQUESTS_PER_MINUTE,
            "RATE_LIMIT_REQUESTS_PER_MINUTE",
        )?;
        let trusted_proxy_cidrs = parse_cidr_list(lookup("TRUSTED_PROXY_CIDRS").as_deref())?;
        if app_env.is_production() && trusted_proxy_cidrs.is_empty() {
            return Err("TRUSTED_PROXY_CIDRS is required when APP_ENV=production".to_string());
        }
        let default_log_format = if app_env.is_production() {
            LogFormat::Json
        } else {
            LogFormat::Plain
        };
        let log_format = match lookup("LOG_FORMAT") {
            Some(value) if !value.trim().is_empty() => LogFormat::from_str(&value)?,
            _ => default_log_format,
        };

        Ok(Self {
            app_env,
            master_key,
            storage_path,
            cors_allowed_origins,
            rate_limit_requests_per_minute,
            trusted_proxy_cidrs,
            log_format,
        })
    }
}

fn parse_cidr_list(raw: Option<&str>) -> Result<Vec<IpNet>, String> {
    raw.unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<IpNet>()
                .map_err(|_| format!("invalid TRUSTED_PROXY_CIDRS entry: {value}"))
        })
        .collect()
}

fn parse_origin_list(raw: Option<&str>) -> Result<Vec<HeaderValue>, String> {
    let mut values = Vec::new();
    if let Some(raw_origins) = raw {
        for origin in raw_origins.split(',') {
            let trimmed = origin.trim();
            if trimmed.is_empty() {
                continue;
            }
            let parsed = HeaderValue::from_str(trimmed)
                .map_err(|_| format!("invalid CORS origin header value: {trimmed}"))?;
            values.push(parsed);
        }
    }
    Ok(values)
}

fn parse_bool(raw: Option<String>) -> Result<bool, String> {
    let Some(raw_value) = raw else {
        return Ok(false);
    };
    match raw_value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!(
            "invalid boolean value: {raw_value} (expected true/false, 1/0, yes/no, on/off)"
        )),
    }
}

fn parse_u64(raw: Option<&str>, default: u64, name: &str) -> Result<u64, String> {
    let Some(raw_value) = raw else {
        return Ok(default);
    };
    let trimmed = raw_value.trim();
    if trimmed.is_empty() {
        return Ok(default);
    }
    trimmed
        .parse::<u64>()
        .map_err(|_| format!("invalid {name}: {raw_value} (expected unsigned integer)"))
}

fn enforce_production_security_gate<F>(lookup: &F) -> Result<(), String>
where
    F: Fn(&str) -> Option<String>,
{
    let high_risk_required = parse_bool(lookup("HIGH_RISK_SIGNATURE_REQUIRED"))?;
    if !high_risk_required {
        return Err("HIGH_RISK_SIGNATURE_REQUIRED=true is required in production".to_string());
    }

    let signing_secret = lookup("HIGH_RISK_SIGNING_SECRET")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "HIGH_RISK_SIGNING_SECRET is required in production".to_string())?;
    if signing_secret == DEV_HIGH_RISK_SIGNING_SECRET {
        return Err("HIGH_RISK_SIGNING_SECRET must not use development default".to_string());
    }

    let auth_pepper = lookup("AUTH_PEPPER")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "AUTH_PEPPER is required in production".to_string())?;
    if auth_pepper == DEV_AUTH_PEPPER {
        return Err("AUTH_PEPPER must not use development default".to_string());
    }

    for key_path_name in ["JWT_PRIVATE_KEY_PATH", "JWT_PUBLIC_KEY_PATH"] {
        let key_path = lookup(key_path_name)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("{key_path_name} is required in production"))?;
        if !Path::new(&key_path).is_file() {
            return Err(format!(
                "{key_path_name} must point to an existing key file"
            ));
        }
    }

    let witness_config_json = lookup("WITNESS_CONFIG_JSON")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let witness_config_file = lookup("WITNESS_CONFIG_FILE")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let witness_keys = lookup("WITNESS_KEYS")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if witness_config_json.is_none() && witness_config_file.is_none() && witness_keys.is_none() {
        return Err(
            "WITNESS_CONFIG_JSON, WITNESS_CONFIG_FILE, or WITNESS_KEYS is required in production"
                .to_string(),
        );
    }
    if witness_keys
        .as_deref()
        .is_some_and(|keys| keys.contains("dev-secret-"))
        || witness_config_json
            .as_deref()
            .is_some_and(|json| json.contains("dev-secret-"))
    {
        return Err("WITNESS_KEYS must not contain development secrets".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{AppConfig, AppEnv, LogFormat};

    fn insert_test_key_paths(env: &mut HashMap<String, String>) {
        env.insert("JWT_PRIVATE_KEY_PATH".to_string(), "Cargo.toml".to_string());
        env.insert("JWT_PUBLIC_KEY_PATH".to_string(), "Cargo.toml".to_string());
    }

    #[test]
    fn defaults_to_development_mode() {
        let cfg = AppConfig::from_lookup(|_| None).expect("config");
        assert_eq!(cfg.app_env, AppEnv::Development);
        assert_eq!(cfg.master_key, "dev-master-key");
        assert!(cfg.cors_allowed_origins.is_empty());
        assert!(cfg.trusted_proxy_cidrs.is_empty());
        assert_eq!(cfg.log_format, LogFormat::Plain);
    }

    #[test]
    fn parses_trusted_proxy_cidrs() {
        let cfg = AppConfig::from_lookup(|name| {
            (name == "TRUSTED_PROXY_CIDRS").then(|| "10.0.0.0/8, 2001:db8::/32".to_string())
        })
        .expect("config");

        assert_eq!(cfg.trusted_proxy_cidrs.len(), 2);
        assert!(
            cfg.trusted_proxy_cidrs[0].contains(&"10.1.2.3".parse::<std::net::IpAddr>().unwrap())
        );
        assert!(cfg.trusted_proxy_cidrs[1]
            .contains(&"2001:db8::1".parse::<std::net::IpAddr>().unwrap()));
    }

    #[test]
    fn rejects_invalid_trusted_proxy_cidrs() {
        let err = AppConfig::from_lookup(|name| {
            (name == "TRUSTED_PROXY_CIDRS").then(|| "not-a-cidr".to_string())
        })
        .expect_err("invalid cidr must fail");

        assert!(err.contains("TRUSTED_PROXY_CIDRS"));
    }

    #[test]
    fn production_requires_security_variables() {
        let mut env = HashMap::new();
        env.insert("APP_ENV".to_string(), "production".to_string());
        env.insert("MASTER_KEY".to_string(), "secure-master-key".to_string());
        env.insert(
            "CORS_ALLOWED_ORIGINS".to_string(),
            "https://hypertide.example.com".to_string(),
        );

        let err = AppConfig::from_lookup(|name| env.get(name).cloned()).expect_err("must fail");
        assert!(
            err.contains("HIGH_RISK_SIGNATURE_REQUIRED"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn production_accepts_strict_configuration() {
        let mut env = HashMap::new();
        env.insert("APP_ENV".to_string(), "production".to_string());
        env.insert("MASTER_KEY".to_string(), "secure-master-key".to_string());
        env.insert(
            "CORS_ALLOWED_ORIGINS".to_string(),
            "https://hypertide.example.com".to_string(),
        );
        env.insert(
            "HIGH_RISK_SIGNATURE_REQUIRED".to_string(),
            "true".to_string(),
        );
        env.insert(
            "HIGH_RISK_SIGNING_SECRET".to_string(),
            "secure-signing-secret".to_string(),
        );
        env.insert("AUTH_PEPPER".to_string(), "secure-pepper".to_string());
        env.insert(
            "TRUSTED_PROXY_CIDRS".to_string(),
            "172.16.0.0/12".to_string(),
        );
        insert_test_key_paths(&mut env);
        env.insert(
            "WITNESS_KEYS".to_string(),
            "w1:prod-secret-1:region-a,w2:prod-secret-2:region-b".to_string(),
        );

        let cfg = AppConfig::from_lookup(|name| env.get(name).cloned()).expect("config");
        assert_eq!(cfg.app_env, AppEnv::Production);
        assert_eq!(cfg.cors_allowed_origins.len(), 1);
    }

    #[test]
    fn production_accepts_structured_witness_config() {
        let mut env = HashMap::new();
        env.insert("APP_ENV".to_string(), "production".to_string());
        env.insert("MASTER_KEY".to_string(), "secure-master-key".to_string());
        env.insert(
            "CORS_ALLOWED_ORIGINS".to_string(),
            "https://hypertide.example.com".to_string(),
        );
        env.insert(
            "HIGH_RISK_SIGNATURE_REQUIRED".to_string(),
            "true".to_string(),
        );
        env.insert(
            "HIGH_RISK_SIGNING_SECRET".to_string(),
            "secure-signing-secret".to_string(),
        );
        env.insert("AUTH_PEPPER".to_string(), "secure-pepper".to_string());
        env.insert(
            "TRUSTED_PROXY_CIDRS".to_string(),
            "172.16.0.0/12".to_string(),
        );
        insert_test_key_paths(&mut env);
        env.insert(
            "WITNESS_CONFIG_JSON".to_string(),
            r#"{"witnesses":[{"id":"w1","secret":"prod-secret-1","scope":"region-a","environment":"studio-a"},{"id":"w2","secret":"prod-secret-2","scope":"region-b","environment":"studio-b"}],"quorum":2,"scope":"cross-env"}"#.to_string(),
        );

        let cfg = AppConfig::from_lookup(|name| env.get(name).cloned()).expect("config");
        assert_eq!(cfg.app_env, AppEnv::Production);
    }

    #[test]
    fn production_defaults_to_json_logs() {
        let mut env = HashMap::new();
        env.insert("APP_ENV".to_string(), "production".to_string());
        env.insert("MASTER_KEY".to_string(), "secure-master-key".to_string());
        env.insert(
            "CORS_ALLOWED_ORIGINS".to_string(),
            "https://hypertide.example.com".to_string(),
        );
        env.insert(
            "HIGH_RISK_SIGNATURE_REQUIRED".to_string(),
            "true".to_string(),
        );
        env.insert(
            "HIGH_RISK_SIGNING_SECRET".to_string(),
            "secure-signing-secret".to_string(),
        );
        env.insert("AUTH_PEPPER".to_string(), "secure-pepper".to_string());
        env.insert(
            "TRUSTED_PROXY_CIDRS".to_string(),
            "172.16.0.0/12".to_string(),
        );
        insert_test_key_paths(&mut env);
        env.insert(
            "WITNESS_KEYS".to_string(),
            "w1:prod-secret-1:region-a,w2:prod-secret-2:region-b".to_string(),
        );

        let cfg = AppConfig::from_lookup(|name| env.get(name).cloned()).expect("config");
        assert_eq!(cfg.log_format, LogFormat::Json);
    }
}

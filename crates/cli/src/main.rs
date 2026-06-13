use anyhow::Result;
use clap::{Parser, Subcommand};

mod cmd;
mod utils;
mod workspace;

#[derive(Debug, Parser)]
#[command(
    name = "ht",
    version,
    about = "HyperTide CLI",
    long_about = "HyperTide CLI for logging in, syncing assets, staging local changes, and submitting asset versions."
)]
struct Cli {
    #[arg(long, global = true, help = "Output in JSON format")]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Save server credentials and defaults")]
    Login(cmd::login::LoginArgs),
    #[command(about = "Initialize the current workspace for a repo")]
    Init(cmd::init::InitArgs),
    #[command(about = "Create, list, inspect, or select repositories")]
    Repo(cmd::repo::RepoArgs),
    #[command(about = "Create, list, or switch branches")]
    Branch(cmd::branch::BranchArgs),
    #[command(
        about = "Stage a local file or existing blob",
        long_about = "Stage a file for the next submit.\n\n  ht add --file <local-file> [--asset-path <repo-path>]\n    Upload the local file and stage it under the given repo path.\n    If --asset-path is omitted the local file name is used.\n\n  ht add --blob <hash> --asset-path <repo-path>\n    Stage an already-uploaded blob by its hash."
    )]
    Add(cmd::add::AddArgs),
    #[command(
        about = "Stage an asset removal",
        long_about = "Mark an asset for removal in the next submit.\n\n  ht remove --asset-path <repo-path>"
    )]
    Remove(cmd::remove::RemoveArgs),
    #[command(about = "Save workspace progress (does not advance branch head)")]
    Save(cmd::save::SaveArgs),
    #[command(about = "Create, restore, or branch from workspace checkpoints")]
    Checkpoint(cmd::checkpoint::CheckpointArgs),
    #[command(about = "Approve, promote, or inspect changesets")]
    Changeset(cmd::changeset::ChangesetArgs),
    #[command(about = "Acquire, release, renew, or inspect locks")]
    Lock(cmd::lock::LockArgs),
    #[command(about = "Run trust, witness, audit, replay, and retention operations")]
    Trust(cmd::trust::TrustArgs),
    #[command(about = "Submit staged asset changes")]
    Submit(cmd::submit::SubmitArgs),
    #[command(about = "Show changeset history")]
    Log(cmd::log_cmd::LogArgs),
    #[command(about = "Submit a rollback changeset")]
    Rollback(cmd::rollback::RollbackArgs),
    #[command(about = "Recover a single asset from a previous snapshot")]
    Revert(cmd::revert::RevertArgs),
    #[command(about = "Sync local metadata to a branch snapshot")]
    Sync(cmd::sync::SyncArgs),
    #[command(about = "Materialize branch assets into the workspace")]
    Checkout(cmd::checkout::CheckoutArgs),
    #[command(about = "Show asset status for the workspace")]
    Status(cmd::status::StatusArgs),
    #[command(about = "Show asset-level hash differences")]
    Diff(cmd::diff::DiffArgs),
    #[command(about = "Upload a large file through chunk storage")]
    ChunkUpload(cmd::chunk_upload::ChunkUploadArgs),
    #[command(about = "Inspect or clear the staging area")]
    Stage(cmd::stage::StageArgs),
    #[command(about = "Generate shell completion scripts")]
    Completions(cmd::completions::CompletionsArgs),
    #[command(about = "Check login, connectivity, and workspace health")]
    Doctor(cmd::doctor::DoctorArgs),
    #[command(about = "Inspect and validate HyperTide server operations")]
    Server(cmd::server::ServerArgs),
}

#[allow(dead_code)]
fn parse_cli_from<I, T>(iter: I) -> std::result::Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    Cli::try_parse_from(iter)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    utils::set_json_output(cli.json);
    match cli.command {
        Command::Login(args) => cmd::login::execute(args).await,
        Command::Init(args) => cmd::init::execute(args).await,
        Command::Repo(args) => cmd::repo::execute(args).await,
        Command::Branch(args) => cmd::branch::execute(args).await,
        Command::Add(args) => cmd::add::execute(args).await,
        Command::Remove(args) => cmd::remove::execute(args).await,
        Command::Save(args) => cmd::save::execute(args).await,
        Command::Checkpoint(args) => cmd::checkpoint::execute(args).await,
        Command::Changeset(args) => cmd::changeset::execute(args).await,
        Command::Lock(args) => cmd::lock::execute(args).await,
        Command::Trust(args) => cmd::trust::execute(args).await,
        Command::Submit(args) => cmd::submit::execute(args).await,
        Command::Log(args) => cmd::log_cmd::execute(args).await,
        Command::Rollback(args) => cmd::rollback::execute(args).await,
        Command::Revert(args) => cmd::revert::execute(args).await,
        Command::Sync(args) => cmd::sync::execute(args).await,
        Command::Checkout(args) => cmd::checkout::execute(args).await,
        Command::Status(args) => cmd::status::execute(args).await,
        Command::Diff(args) => cmd::diff::execute(args).await,
        Command::ChunkUpload(args) => cmd::chunk_upload::execute(args).await,
        Command::Stage(args) => cmd::stage::execute(args).await,
        Command::Completions(args) => cmd::completions::execute(args),
        Command::Doctor(args) => cmd::doctor::execute(args).await,
        Command::Server(args) => cmd::server::execute(args).await,
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn parse_commands_baseline() {
        let cases = vec![
            vec!["ht", "login", "--server", "http://x", "--token", "t"],
            vec!["ht", "init", "--repo", "r"],
            vec!["ht", "repo", "create", "r"],
            vec!["ht", "repo", "list"],
            vec!["ht", "repo", "info"],
            vec!["ht", "repo", "use", "r"],
            vec!["ht", "branch", "create", "--repo", "r", "--name", "feat"],
            vec!["ht", "branch", "list", "--repo", "r"],
            vec!["ht", "branch", "switch", "--repo", "r", "--name", "main"],
            vec!["ht", "add", "--asset-path", "a", "--blob", "b"],
            vec!["ht", "remove", "--asset-path", "a"],
            vec!["ht", "submit"],
            vec!["ht", "log"],
            vec!["ht", "rollback", "--to", "c1"],
            vec!["ht", "sync"],
            vec!["ht", "checkout"],
            vec!["ht", "status"],
            vec!["ht", "diff"],
            vec!["ht", "chunk-upload", "--file", "f.bin"],
        ];
        for case in cases {
            assert!(parse_cli_from(case).is_ok());
        }
    }

    fn command_help(mut cmd: clap::Command) -> String {
        let mut out = Vec::new();
        cmd.write_long_help(&mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn help_snapshot_contains_key_fragments() {
        let root = command_help(Cli::command());
        for fragment in [
            "login",
            "init",
            "repo",
            "branch",
            "add",
            "remove",
            "submit",
            "log",
            "rollback",
            "sync",
            "checkout",
            "status",
            "diff",
            "chunk-upload",
        ] {
            assert!(root.contains(fragment), "missing fragment: {fragment}");
        }
        let login = command_help(Cli::command().find_subcommand("login").unwrap().clone());
        assert!(login.contains("--branch"));
        assert!(login.contains("[default: main]"));
        let log_help = command_help(Cli::command().find_subcommand("log").unwrap().clone());
        assert!(log_help.contains("--limit"));
        assert!(log_help.contains("[default: 20]"));
        let chunk_help = command_help(
            Cli::command()
                .find_subcommand("chunk-upload")
                .unwrap()
                .clone(),
        );
        assert!(chunk_help.contains("--chunk-size-policy"));
        assert!(chunk_help.contains("[default: fixed-4m]"));
    }

    #[test]
    fn checkout_accepts_repo_branch_and_to_flags() {
        assert!(Cli::try_parse_from(["ht", "checkout"]).is_ok());
        assert!(Cli::try_parse_from(["ht", "checkout", "--repo", "r", "--branch", "dev"]).is_ok());
        assert!(Cli::try_parse_from([
            "ht", "checkout", "--repo", "r", "--branch", "dev", "--to", "cs-1",
        ])
        .is_ok());
    }

    #[test]
    fn checkout_accepts_force_flag() {
        assert!(Cli::try_parse_from(["ht", "checkout", "--force"]).is_ok());
        assert!(Cli::try_parse_from([
            "ht", "checkout", "--repo", "r", "--branch", "dev", "--force",
        ])
        .is_ok());
    }

    #[test]
    fn checkout_accepts_dry_run_flag() {
        assert!(Cli::try_parse_from(["ht", "checkout", "--dry-run"]).is_ok());
        assert!(Cli::try_parse_from([
            "ht",
            "checkout",
            "--repo",
            "r",
            "--branch",
            "dev",
            "--to",
            "cs-1",
            "--dry-run",
        ])
        .is_ok());
    }

    #[test]
    fn branch_switch_accepts_force_flag() {
        assert!(
            Cli::try_parse_from(["ht", "branch", "switch", "--name", "main", "--force"]).is_ok()
        );
    }

    #[test]
    fn repo_commands_accept_expected_flags() {
        assert!(Cli::try_parse_from([
            "ht",
            "repo",
            "create",
            "game-assets",
            "--default-branch",
            "main",
            "--use",
            "--force",
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["ht", "repo", "list"]).is_ok());
        assert!(Cli::try_parse_from(["ht", "repo", "info"]).is_ok());
        assert!(Cli::try_parse_from(["ht", "repo", "info", "game-assets"]).is_ok());
        assert!(Cli::try_parse_from([
            "ht",
            "repo",
            "use",
            "game-assets",
            "--branch",
            "dev",
            "--force",
        ])
        .is_ok());
    }

    #[test]
    fn init_accepts_repo_branch_and_force() {
        assert!(Cli::try_parse_from([
            "ht",
            "init",
            "--repo",
            "game-assets",
            "--branch",
            "main",
            "--force",
        ])
        .is_ok());
    }

    #[test]
    fn server_doctor_accepts_env_file_and_server_url() {
        assert!(Cli::try_parse_from([
            "ht",
            "server",
            "doctor",
            "--env-file",
            "deploy/server/.env.production",
            "--server-url",
            "https://hypertide.example.com",
        ])
        .is_ok());
    }

    #[test]
    fn add_without_input_fails_at_argument_validation() {
        let error = Cli::try_parse_from(["ht", "add"]).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("--file <FILE>"));
        assert!(message.contains("--blob <BLOB>"));
    }

    #[test]
    fn branch_commands_accept_repo_from_profile_default() {
        assert!(Cli::try_parse_from(["ht", "branch", "create", "--name", "feature/test"]).is_ok());
        assert!(Cli::try_parse_from(["ht", "branch", "list"]).is_ok());
        assert!(Cli::try_parse_from(["ht", "branch", "switch", "--name", "main"]).is_ok());
    }

    #[test]
    fn top_level_help_includes_session_checkpoint_commands() {
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("Save workspace progress"));
        assert!(help.contains("Create, restore, or branch from workspace checkpoints"));
        assert!(help.contains("Approve, promote, or inspect changesets"));
        assert!(help.contains("Acquire, release, renew, or inspect locks"));
        assert!(help.contains("Run trust, witness, audit, replay, and retention operations"));
    }

    #[test]
    fn submit_accepts_checkpoint_and_visibility_flags() {
        let mut command = Cli::command();
        let submit = command
            .find_subcommand_mut("submit")
            .expect("submit command")
            .render_long_help()
            .to_string();
        assert!(submit.contains("--from-checkpoint"));
        assert!(submit.contains("--visibility"));
    }

    #[test]
    fn changeset_commands_accept_required_flags() {
        assert!(Cli::try_parse_from([
            "ht",
            "changeset",
            "approve",
            "--repo",
            "repo-a",
            "--id",
            "cs-1",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "ht",
            "changeset",
            "promote",
            "--repo",
            "repo-a",
            "--id",
            "cs-1",
            "--high-risk-secret",
            "secret",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "ht",
            "changeset",
            "gate",
            "--repo",
            "repo-a",
            "--id",
            "cs-1",
        ])
        .is_ok());
    }

    #[test]
    fn lock_commands_accept_paths_and_high_risk_secret() {
        assert!(
            Cli::try_parse_from(["ht", "lock", "acquire", "--path", "Content/a.uasset"]).is_ok()
        );
        assert!(
            Cli::try_parse_from(["ht", "lock", "release", "--path", "Content/a.uasset"]).is_ok()
        );
        assert!(Cli::try_parse_from(["ht", "lock", "renew", "--path", "Content/a.uasset"]).is_ok());
        assert!(Cli::try_parse_from(["ht", "lock", "list"]).is_ok());
        assert!(Cli::try_parse_from([
            "ht",
            "lock",
            "force-release",
            "--path",
            "Content/a.uasset",
            "--high-risk-secret",
            "secret",
        ])
        .is_ok());
    }

    #[test]
    fn trust_commands_accept_governance_arguments() {
        assert!(Cli::try_parse_from(["ht", "trust", "checkpoint", "generate"]).is_ok());
        assert!(Cli::try_parse_from(["ht", "trust", "checkpoint", "latest"]).is_ok());
        assert!(Cli::try_parse_from([
            "ht",
            "trust",
            "witness",
            "attest",
            "--checkpoint",
            "tc-1",
            "--witness",
            "witness-a",
        ])
        .is_ok());
        assert!(
            Cli::try_parse_from(["ht", "trust", "witness", "summary", "--checkpoint", "tc-1"])
                .is_ok()
        );
        assert!(Cli::try_parse_from(["ht", "trust", "witness", "topology"]).is_ok());
        assert!(Cli::try_parse_from(["ht", "trust", "audit", "verify"]).is_ok());
        assert!(Cli::try_parse_from([
            "ht",
            "trust",
            "audit",
            "export",
            "--limit",
            "10",
            "--before-seq",
            "99",
            "--action",
            "CHANGESET_PROMOTED",
            "--actor",
            "alice",
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["ht", "trust", "replay", "verify"]).is_ok());
        assert!(Cli::try_parse_from(["ht", "trust", "replay", "readiness"]).is_ok());
        assert!(Cli::try_parse_from(["ht", "trust", "retention", "policy"]).is_ok());
    }

    #[test]
    fn checkpoint_list_accepts_optional_session() {
        assert!(Cli::try_parse_from(["ht", "checkpoint", "list"]).is_ok());
        assert!(Cli::try_parse_from(["ht", "checkpoint", "list", "--session", "sess-1"]).is_ok());
    }

    #[test]
    fn remove_requires_asset_path() {
        let result = Cli::try_parse_from(["ht", "remove"]);
        assert!(result.is_err());
    }

    #[test]
    fn remove_accepts_asset_path_and_branch() {
        assert!(
            Cli::try_parse_from(["ht", "remove", "--asset-path", "Content/old.uasset"]).is_ok()
        );
        assert!(Cli::try_parse_from([
            "ht",
            "remove",
            "--asset-path",
            "Content/old.uasset",
            "--branch",
            "dev",
        ])
        .is_ok());
    }

    #[test]
    fn chunk_upload_accepts_all_flags() {
        assert!(Cli::try_parse_from([
            "ht",
            "chunk-upload",
            "--file",
            "big.bin",
            "--chunk-size",
            "8388608",
            "--chunk-size-policy",
            "fixed-8m",
            "--manifest-only",
        ])
        .is_ok());
    }

    #[test]
    fn chunk_upload_defaults_are_correct() {
        let matches = Cli::try_parse_from(["ht", "chunk-upload", "--file", "f.bin"]).unwrap();
        if let Command::ChunkUpload(args) = matches.command {
            assert_eq!(args.chunk_size, 4 * 1024 * 1024);
            assert_eq!(args.chunk_size_policy, "fixed-4m");
            assert!(!args.manifest_only);
        } else {
            panic!("expected ChunkUpload command");
        }
    }
}

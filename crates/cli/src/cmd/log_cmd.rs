use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use clap::Args;

use crate::utils::*;

#[derive(Debug, Args)]
pub(crate) struct LogArgs {
    #[arg(long, help = "Repository id; defaults to the login profile repository")]
    pub repo: Option<String>,
    #[arg(long, help = "Branch to inspect; defaults to the login profile branch")]
    pub branch: Option<String>,
    #[arg(
        long,
        default_value_t = 20,
        help = "Maximum number of changesets to show"
    )]
    pub limit: usize,
    #[arg(long, help = "Show parent-child graph")]
    pub graph: bool,
}

pub(crate) async fn execute(args: LogArgs) -> Result<()> {
    let mut profile = load_profile()?;
    let repo = resolve_repo(&profile, args.repo.as_deref())?;
    let branch = args
        .branch
        .unwrap_or_else(|| profile.current_branch.clone());
    let client = reqwest::Client::new();
    let url = format!(
        "{}/v2/changesets?repo_id={}&branch={}&limit={}",
        profile.server.trim_end_matches('/'),
        repo,
        branch,
        args.limit
    );
    let response: ApiResponse<HistoryPage> = send_authed_api(
        &client,
        &mut profile,
        |client, profile| with_auth(client.get(&url), profile),
        "log response decode failed",
    )
    .await?;
    if !response.success {
        return Err(anyhow!(api_error_message(&response, "log failed")));
    }
    let data = response.data.context("missing response data")?;
    if json_output_enabled() {
        println!("{}", serde_json::to_string_pretty(&data.items)?);
    } else if args.graph {
        print_graph(&data.items);
    } else {
        for cs in data.items {
            println!(
                "{}  {}  {}  {}",
                &cs.changeset_id[..8.min(cs.changeset_id.len())],
                cs.created_at,
                cs.author,
                cs.message
            );
        }
    }
    Ok(())
}

/// Render an ASCII graph of changeset parent-child relationships.
fn print_graph(items: &[ChangesetRecord]) {
    if items.is_empty() {
        println!("no changesets");
        return;
    }

    // Build id→index map
    let id_index: HashMap<&str, usize> = items
        .iter()
        .enumerate()
        .map(|(i, cs)| (cs.changeset_id.as_str(), i))
        .collect();

    // Assign columns: each changeset gets a column; merges collapse to parent's column
    let mut columns: Vec<usize> = Vec::with_capacity(items.len());
    let mut next_col: usize = 0;
    let mut active_cols: Vec<usize> = Vec::new(); // columns with active "lines"

    for cs in items.iter() {
        let col = if let Some(parent_id) = &cs.parent_changeset_id {
            if let Some(&parent_idx) = id_index.get(parent_id.as_str()) {
                // Parent is in the list — reuse its column
                columns[parent_idx]
            } else {
                // Parent not in list — new column
                let c = next_col;
                next_col += 1;
                c
            }
        } else {
            // No parent — new column
            let c = next_col;
            next_col += 1;
            c
        };
        columns.push(col);
        if !active_cols.contains(&col) {
            active_cols.push(col);
        }
    }

    // Render
    let max_col = columns.iter().copied().max().unwrap_or(0);
    for (i, cs) in items.iter().enumerate() {
        let col = columns[i];
        let short_id = &cs.changeset_id[..8.min(cs.changeset_id.len())];
        let date = &cs.created_at[..10.min(cs.created_at.len())];

        // Build the graph prefix
        let mut prefix = String::new();
        for c in 0..=max_col {
            if c == col {
                prefix.push('*');
            } else if active_cols.contains(&c) {
                prefix.push('|');
            } else {
                prefix.push(' ');
            }
            if c < max_col {
                prefix.push(' ');
            }
        }

        println!(
            "{} {} {} {} {}",
            prefix, short_id, date, cs.author, cs.message
        );
    }
}

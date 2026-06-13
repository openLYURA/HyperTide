use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::Args;

use crate::utils::*;

#[derive(Debug, Args)]
pub(crate) struct ChunkUploadArgs {
    #[arg(long, help = "Local file to upload through chunk storage")]
    pub file: String,
    #[arg(long, default_value_t = 4 * 1024 * 1024, help = "Chunk size in bytes")]
    pub chunk_size: usize,
    #[arg(
        long,
        default_value = "fixed-4m",
        help = "Chunk size policy recorded in the manifest"
    )]
    pub chunk_size_policy: String,
    #[arg(
        long,
        default_value_t = false,
        help = "Create only the manifest without composing a final blob"
    )]
    pub manifest_only: bool,
}

pub(crate) async fn execute(args: ChunkUploadArgs) -> Result<()> {
    let mut profile = load_profile()?;
    let client = reqwest::Client::new();
    let file_path = PathBuf::from(&args.file);
    let bytes = fs::read(&file_path)
        .with_context(|| format!("failed to read file {}", file_path.display()))?;

    if bytes.is_empty() {
        return Err(anyhow!("file is empty"));
    }
    let blob = upload_blob_via_chunks(
        &client,
        &mut profile,
        &file_path,
        &bytes,
        args.chunk_size,
        &args.chunk_size_policy,
        args.manifest_only,
    )
    .await?;

    if !args.manifest_only {
        cache_blob(&blob.blob_hash, &bytes)?;
    }
    if json_output_enabled() {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "ok": true,
            "blob_hash": blob.blob_hash,
            "size_bytes": blob.size_bytes,
            "manifest_only": args.manifest_only,
        }))?);
    } else if args.manifest_only {
        println!(
            "chunk-upload manifest-only: manifest_hash={} size_bytes={}",
            blob.blob_hash, blob.size_bytes
        );
    } else {
        println!(
            "chunk-upload done: blob_hash={} size_bytes={}",
            blob.blob_hash, blob.size_bytes
        );
    }
    Ok(())
}

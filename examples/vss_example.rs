//! VSS backup usage example
//!
//! Demonstrates basic VSS (Versioned Storage Service) backup operations:
//! creating a client, uploading, downloading, and verifying backup data.
//!
//! Run with:
//! ```
//! cargo run --example vss_example --features vss
//! ```
//!
//! Environment variables:
//! - `VSS_SERVER_URL`: URL of the VSS server (default: http://localhost:8081/vss)

use std::io::Write;

use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::secp256k1::rand::rngs::OsRng;
use rgb_lib::wallet::vss::{VssBackupClient, VssBackupConfig};
use zip::write::SimpleFileOptions;

const DEFAULT_VSS_SERVER_URL: &str = "http://localhost:8081/vss";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vss_server_url =
        std::env::var("VSS_SERVER_URL").unwrap_or_else(|_| DEFAULT_VSS_SERVER_URL.to_string());

    // Generate a random signing key (in production, derive from wallet mnemonic)
    let secp = Secp256k1::new();
    let (signing_key, public_key) = secp.generate_keypair(&mut OsRng);
    let store_id = format!("example_{}", hex::encode(&public_key.serialize()[0..8]));

    // 1. Create a VssBackupConfig (encryption enabled by default)
    let config = VssBackupConfig::new(vss_server_url, store_id, signing_key);

    // 2. Create a VssBackupClient
    let client = VssBackupClient::new(config)?;

    // 3. Prepare backup data (a zip with a fingerprint-named directory)
    let backup_data = create_sample_zip("a1b2c3d4", b"sample wallet data")?;
    println!("Uploading {} bytes...", backup_data.len());

    // 4. Upload
    let version = client.upload_backup(backup_data.clone()).await?;
    println!("Uploaded, version: {version}");

    // 5. Download and verify
    let downloaded = client.download_backup().await?;
    assert_eq!(downloaded, backup_data, "round-trip data mismatch");
    println!("Downloaded and verified {} bytes", downloaded.len());

    // 6. Clean up
    client.delete_backup().await?;
    println!("Backup deleted");

    Ok(())
}

fn create_sample_zip(
    fingerprint: &str,
    content: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.add_directory(format!("{fingerprint}/"), opts)?;
        zip.start_file(format!("{fingerprint}/data.bin"), opts)?;
        zip.write_all(content)?;
        zip.finish()?;
    }
    Ok(buf.into_inner())
}

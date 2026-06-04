use ed25519_dalek::{SigningKey, Signer};
use rand_core::{OsRng, RngCore};
use std::fs;
use std::io::Write;
use std::path::Path;
use zip::ZipWriter;
use zip::write::FileOptions;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure test directory exists
    fs::create_dir_all("test")?;

    // Generate OS-backed entropy key using ed25519-dalek v2.2 API
    let mut csprng = OsRng;
    let mut secret_bytes = [0u8; 32];
    csprng.fill_bytes(&mut secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verify_key = signing_key.verifying_key();

    // Write public key in hex format
    let pubkey_hex = hex::encode(verify_key.to_bytes());
    fs::write("test/pubkey.hex", &pubkey_hex)?;
    println!("✓ Generated and saved public key to test/pubkey.hex");
    println!("  Public key (hex): {}", pubkey_hex);

    // Read or create job.evk content for signing
    let job_evk_path = "job.evk";
    let job_evk_content = if Path::new(job_evk_path).exists() {
        fs::read(job_evk_path)?
    } else {
        // Create a sample job.evk if it doesn't exist
        let sample = b"job.evk:fixture:data:v1";
        fs::write(job_evk_path, sample)?;
        sample.to_vec()
    };

    // Sign the job.evk content
    let signature = signing_key.sign(&job_evk_content);
    let signature_hex = hex::encode(signature.to_bytes());
    println!("✓ Signed job.evk content");
    println!("  Signature (hex): {}", signature_hex);

    // Create ZIP archive with job.evk and job.evk.sig
    let zip_path = "job.evk.zip";
    let file = fs::File::create(zip_path)?;
    let mut zip = ZipWriter::new(file);

    // Add job.evk to ZIP
    let options = FileOptions::default();
    zip.start_file("job.evk", options)?;
    zip.write_all(&job_evk_content)?;

    // Add job.evk.sig (signature in hex format) to ZIP
    zip.start_file("job.evk.sig", options)?;
    zip.write_all(signature_hex.as_bytes())?;

    zip.finish()?;
    println!("✓ Created ZIP archive: {}", zip_path);
    println!("  Contents: job.evk, job.evk.sig");

    Ok(())
}

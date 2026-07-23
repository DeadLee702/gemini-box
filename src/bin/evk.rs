use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::env;
use std::io::Read;
use std::path::PathBuf;
use zip::ZipArchive;

fn load_pubkey() -> Result<[u8; 32], String> {
    let pubkey_path = env::var("Z12_PUBKEY_HEX")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("test/pubkey.hex"));

    let pubkey_hex = std::fs::read_to_string(&pubkey_path)
        .map_err(|e| format!("Failed to read public key from {}: {}", pubkey_path.display(), e))?;

    let pubkey_bytes = hex::decode(pubkey_hex.trim())
        .map_err(|e| format!("Failed to decode public key hex: {}", e))?;

    pubkey_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Public key must be exactly 32 bytes".to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let zip_path = if args.len() >= 2 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from("job.evk.zip")
    };

    println!("EVK Signature Verification Tool");
    println!("================================\n");

    let pubkey_array = load_pubkey()?;

    let verify_key = VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|e| format!("Invalid public key: {}", e))?;

    println!("Loaded public key (hex): {}", hex::encode(&pubkey_array));

    let file = std::fs::File::open(&zip_path)
        .map_err(|e| format!("Failed to open ZIP file {}: {}", zip_path.display(), e))?;

    let mut archive =
        ZipArchive::new(file).map_err(|e| format!("Failed to read ZIP archive: {}", e))?;

    let mut job_evk_content = Vec::new();
    archive
        .by_name("job.evk")
        .map_err(|e| format!("Failed to find job.evk in ZIP: {}", e))?
        .read_to_end(&mut job_evk_content)
        .map_err(|e| format!("Failed to read job.evk: {}", e))?;

    println!(
        "Extracted job.evk from ZIP ({} bytes)",
        job_evk_content.len()
    );

    let mut signature_bytes_vec = Vec::new();
    archive
        .by_name("job.evk.sig")
        .map_err(|e| format!("Failed to find job.evk.sig in ZIP: {}", e))?
        .read_to_end(&mut signature_bytes_vec)
        .map_err(|e| format!("Failed to read job.evk.sig: {}", e))?;

    let signature_hex = String::from_utf8(signature_bytes_vec)
        .map_err(|e| format!("Failed to parse signature as UTF-8: {}", e))?;

    println!("Extracted job.evk.sig from ZIP");
    println!("  Signature (hex): {}", signature_hex.trim());

    let signature_bytes = hex::decode(signature_hex.trim())
        .map_err(|e| format!("Failed to decode signature hex: {}", e))?;

    let signature_array: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Signature must be exactly 64 bytes")?;

    let signature = Signature::from_bytes(&signature_array);

    match verify_key.verify(&job_evk_content, &signature) {
        Ok(()) => {
            println!("\nSUCCESS: Signature verification passed");
            println!("  job.evk authenticity confirmed");
            Ok(())
        }
        Err(_) => {
            eprintln!("\nALERT: INVALID FORGERY DETECTED");
            eprintln!("  Signature verification failed!");
            eprintln!("  The job.evk content or signature has been tampered with.");
            std::process::exit(1);
        }
    }
}

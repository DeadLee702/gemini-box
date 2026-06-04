use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use std::io::Read;
use zip::ZipArchive;

// SANS Challenge Gauntlet: Active - Cryptographic validation tests in progress
// Include the public key from test/pubkey.hex at compile time
const PUBKEY_HEX: &str = include_str!("../../test/pubkey.hex");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("EVK Signature Verification Tool");
    println!("================================\n");

    // Parse the public key from hex
    let pubkey_bytes = hex::decode(PUBKEY_HEX.trim())
        .map_err(|e| format!("Failed to decode public key hex: {}", e))?;

    let verify_key = VerifyingKey::from_bytes(&pubkey_bytes.as_slice().try_into()?)
        .map_err(|e| format!("Invalid public key: {}", e))?;

    println!("✓ Loaded public key (hex): {}", PUBKEY_HEX.trim());

    // Extract and verify signature from ZIP
    let zip_path = "job.evk.zip";
    let file = std::fs::File::open(zip_path)
        .map_err(|e| format!("Failed to open ZIP file {}: {}", zip_path, e))?;

    let mut archive = ZipArchive::new(file)
        .map_err(|e| format!("Failed to read ZIP archive: {}", e))?;

    // Extract job.evk content
    let mut job_evk_content = Vec::new();
    archive
        .by_name("job.evk")
        .map_err(|e| format!("Failed to find job.evk in ZIP: {}", e))?
        .read_to_end(&mut job_evk_content)
        .map_err(|e| format!("Failed to read job.evk: {}", e))?;

    println!("✓ Extracted job.evk from ZIP ({} bytes)", job_evk_content.len());

    // Extract signature from ZIP
    let mut signature_bytes_vec = Vec::new();
    archive
        .by_name("job.evk.sig")
        .map_err(|e| format!("Failed to find job.evk.sig in ZIP: {}", e))?
        .read_to_end(&mut signature_bytes_vec)
        .map_err(|e| format!("Failed to read job.evk.sig: {}", e))?;

    let signature_hex = String::from_utf8(signature_bytes_vec)
        .map_err(|e| format!("Failed to parse signature as UTF-8: {}", e))?;

    println!("✓ Extracted job.evk.sig from ZIP");
    println!("  Signature (hex): {}", signature_hex.trim());

    // Decode signature from hex
    let signature_bytes = hex::decode(signature_hex.trim())
        .map_err(|e| format!("Failed to decode signature hex: {}", e))?;

    let signature = Signature::from_bytes(&signature_bytes.as_slice().try_into()?)
        .map_err(|e| format!("Invalid signature format: {}", e))?;

    // Verify the signature using the Verifier trait
    match verify_key.verify(&job_evk_content, &signature) {
        Ok(()) => {
            println!("\n✅ SUCCESS: Signature verification passed");
            println!("   job.evk authenticity confirmed");
            Ok(())
        }
        Err(_) => {
            println!("\n❌ ALERT: INVALID FORGERY DETECTED");
            println!("   Signature verification failed!");
            println!("   The job.evk content or signature has been tampered with.");
            Err("Forgery detected: signature verification failed".into())
        }
    }
}

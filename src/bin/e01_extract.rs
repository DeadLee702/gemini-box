use std::path::PathBuf;
use anyhow::Result;
use gemini_box::E01Reader;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: e01_extract <path_to_e01_image>");
        eprintln!("Example: e01_extract /path/to/nist_m57.E01");
        std::process::exit(1);
    }

    let e01_path = &args[1];
    
    println!("[*] Opening E01 image: {}", e01_path);
    let reader = E01Reader::open(e01_path)?;

    println!("[*] Reading metadata...");
    let metadata = reader.get_metadata()?;
    println!("[+] Format: {}", metadata.format);
    println!("[+] Sectors: {}", metadata.total_sectors);
    println!("[+] Sector size: {} bytes", metadata.sector_size);

    println!("[*] Extracting artifacts...");
    let artifacts = reader.extract_artifacts()?;
    
    println!("[+] Extracted {} bytes", artifacts.len());
    println!("[+] Status code: 0x{:04X}", 
        u16::from_le_bytes([artifacts[0], artifacts[1]]));

    // Write output bundle
    let output_path = PathBuf::from(e01_path)
        .file_stem()
        .map(|s| format!("{}.bin", s.to_string_lossy()))
        .unwrap_or_else(|| "output.bin".to_string());

    std::fs::write(&output_path, &artifacts)?;
    println!("[+] Artifacts written to: {}", output_path);

    Ok(())
}

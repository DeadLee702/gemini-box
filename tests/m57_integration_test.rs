#[cfg(test)]
mod tests {
    use gemini_box::E01Reader;
    use std::path::PathBuf;

    #[test]
    #[ignore] // Ignore until NIST M57 is downloaded
    fn test_nist_m57_e01_extraction() {
        let m57_path = "tests/fixtures/nist_m57/nps-2008-6701.E01";
        
        // Check if NIST M57 file exists
        if !PathBuf::from(m57_path).exists() {
            eprintln!("NIST M57 E01 file not found at: {}", m57_path);
            eprintln!("Download from: http://www.cfreds.nist.gov/data/M57-Patents/");
            eprintln!("Then run: cargo test -- --ignored test_nist_m57_e01_extraction");
            return;
        }

        // Open the E01 image
        let reader = E01Reader::open(m57_path).expect("Failed to open E01");
        
        // Get metadata
        let metadata = reader.get_metadata().expect("Failed to read metadata");
        assert_eq!(metadata.format, "E01 (Encase)");
        assert!(metadata.total_sectors > 0);

        // Extract artifacts
        let artifacts = reader.extract_artifacts().expect("Failed to extract artifacts");
        assert!(!artifacts.is_empty());
        
        // Verify artifact bundle structure
        assert!(artifacts.len() >= 2);
        let status = u16::from_le_bytes([artifacts[0], artifacts[1]]);
        println!("[+] M57 Extraction Status: 0x{:04X}", status);
    }

    #[test]
    #[ignore] // Ignore until NIST M57 is downloaded
    fn test_nist_m57_pipeline() {
        let m57_path = "tests/fixtures/nist_m57/nps-2008-6701.E01";
        
        if !PathBuf::from(m57_path).exists() {
            return;
        }

        // Full pipeline test
        let reader = E01Reader::open(m57_path).expect("Failed to open E01");
        let artifacts = reader.extract_artifacts().expect("Failed to extract artifacts");
        
        // Write to temp file
        let output_path = "tests/fixtures/nist_m57/extracted.bin";
        std::fs::write(output_path, &artifacts).expect("Failed to write artifacts");
        
        // Verify output exists
        assert!(PathBuf::from(output_path).exists());
        
        println!("[+] Full pipeline test passed");
        println!("[+] Output: {}", output_path);
    }
}

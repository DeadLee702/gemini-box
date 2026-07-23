use anyhow::Result;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: e01_extract <path_to_e01_image>");
        eprintln!("Example: e01_extract /path/to/nist_m57.E01");
        std::process::exit(1);
    }

    let e01_path = &args[1];

    println!("[*] E01Reader not yet implemented");
    println!("[*] Path provided: {}", e01_path);
    println!("[!] TODO: Integrate libewf-sys or pure Rust E01 parser");

    Ok(())
}

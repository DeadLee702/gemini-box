use gemini_box::analyze_incident;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: analyze <path-to-incident.evkp> [<path-to-incident.evkp> ...]");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  analyze test/incident_7f3a.evkp");
        eprintln!("  analyze test/incident_*.evkp");
        std::process::exit(1);
    }

    let mut results = Vec::new();

    for file_path in &args[1..] {
        match analyze_incident(file_path) {
            Ok(analysis) => {
                results.push(analysis);
            }
            Err(e) => {
                eprintln!("Error analyzing {}: {}", file_path, e);
                std::process::exit(1);
            }
        }
    }

    match serde_json::to_string_pretty(&results) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("Error serializing results: {}", e);
            std::process::exit(1);
        }
    }
}

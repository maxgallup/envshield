use clap::Parser;

use envshield::{ShieldResponse, ShieldResponseKind};

/// Program that does some basic schema checking for the environment file
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct InputArgs {
    /// Input schema file
    #[arg(short, long, default_value_t = format!("env.toml"))]
    file: String,

    /// Output will be in json format to be machine readable
    #[arg(short, long, default_value_t = false)]
    json: bool,
}

fn main() {
    let args = InputArgs::parse();
    let response = ShieldResponse::new(&args.file);
    if args.json {
        match serde_json::to_string_pretty(&response) {
            Ok(response) => {
                println!("{}", response);
            }
            Err(_) => {
                println!("{{ \"status\": \"JsonParsingError\" }}")
            }
        }
    } else {
        print!("{}", response);
    }

    match response.kind {
        ShieldResponseKind::Failed { error: _ } => std::process::exit(1),
        ShieldResponseKind::Success { checks_from_env } => {
            let total_missing = checks_from_env.missing_values.len()
                + checks_from_env.missing_default.len()
                + checks_from_env.missing_secrets.len();
            if total_missing > 0 {
                std::process::exit(1)
            }

            std::process::exit(0);
        }
    }
}

//! # envshield
//!
//! `envshield` is a simple tool that enforces variables in an environment according to schema.
//!
//! ## Quick Start
//!
//! ```bash
//! # Install
//! cargo install envshield
//!
//! # Run the command in the same directory as the schema file: env.toml
//! envshield
//! ```
//!
//! The schema defines the expected environment variables that your project depends on. It allows
//! you to specify whether environment variables are optional, have default values or even expected
//! concrete values. Based on the schema, it reports what environment variables are present and
//! whether any of them deviate from expected values. Take the following schema for example:
//!
//! ```toml
//! # Version must be set to "1"
//! version = "1"
//!
//! # Here we define an environment variable with an expected value and (are required to) provide
//! # a description. This helps to self document the environment variables in a complex project.
//! [DOMAIN]
//! value = "https://example.com"
//! description = "The domain used by the application."
//!
//! # Suggests that an environment variable must be present and provides a default for the user
//! # to use.
//! [LOG_LEVEL]
//! default = "warn"
//! description = "Which logging level the program uses [debug, warn or error]"
//!
//! # With just a description it enforces that an environment variable is present, but doesn't
//! # enforce a value. Useful for secrets.
//! [API_KEY]
//! description = "Authentication key used only during local testing."
//!
//! # Truly optional variables will not be enforced.
//! [RUST_BACKTRACE]
//! optional = true
//! description = "When set to 1, captures stack backtrace of an OS Thread"
//!
//! # Values from other variables can be referenced using `{{ KEY }}` syntax.
//! [DATABASE_URL]
//! value = "{{ DOMAIN }}/api/database"
//! description = "Database URL used by the PG database."
//!
//! ```
//!
//! When running `envshield` in an environment that has none of the variables above set we
//! get the following output:
//!
//! ```text
//! $ envshield
//!
//! Parsed:   schema at: ./env.toml
//!
//! Warning:  1 optional variables missing from env:
//!           RUST_BACKTRACE
//!
//! Error:    4 required variables missing from env:
//! (value)   DOMAIN        : 'https://example.com'
//! (value)   DATABASE_URL  : 'https://example.com/api/database'
//! (default) LOG_LEVEL     : 'warn'
//! (secret)  API_KEY
//! ```
//!

use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

pub mod error;
pub use error::ShieldError;
pub mod log;
pub mod node;
pub mod schema;
pub use schema::{EnvMap, FinalizedSchema, SchemaCheck, ValidatedAttribute, ValidatedOptions};

/// The main schema file that is read into memory
const MAX_DISPLAY_LEN: usize = 50;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ShieldStatus {
    /// Something has seriously gone wrong at a low level, nothing the user can do could possibly
    ///  improve the situation
    Hopeless,
    /// With user intervention, the system can still work, some assumptions have not been met
    /// but can be recovered with user intervention.
    Recoverable,
    /// Everything is fine, program is operating as it should be, all invariants and assumptions
    /// have been met
    Operational,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ShieldResponse {
    pub schema_file: String,
    pub status: ShieldStatus,
    pub kind: ShieldResponseKind,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ShieldResponseKind {
    Failed {
        error: String, // this should include the data from the custom Error type's Display impl
    },
    Success {
        checks_from_env: Box<SchemaCheck>,
    },
}

fn truncated(s: &str) -> String {
    if s.len() <= MAX_DISPLAY_LEN {
        s.to_string()
    } else {
        format!("{}...", &s[..MAX_DISPLAY_LEN.saturating_sub(3)])
    }
}

impl Display for ShieldResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            ShieldResponseKind::Failed { error } => {
                let _ = writeln!(f, "{} {}", "Error:".red().bold(), error);

                write!(f, "")
            }
            ShieldResponseKind::Success { checks_from_env } => {
                let _ = writeln!(
                    f,
                    "{}   schema at: ./{}",
                    "Parsed:".green().bold(),
                    self.schema_file
                );

                let total_missing = checks_from_env.missing_values.len()
                    + checks_from_env.missing_default.len()
                    + checks_from_env.missing_secrets.len();

                let num_correct = checks_from_env.existing_subset.len();
                if num_correct > 0 {
                    let _ = writeln!(
                        f,
                        "{} {} variables",
                        "Correct: ".green().bold(),
                        num_correct
                    );

                    if total_missing == 0
                        && checks_from_env.missing_optional.is_empty()
                        && checks_from_env.incorrect_values.is_empty()
                    {
                        let _ = writeln!(f, "{}", "Success!".green().bold(),);
                    }
                }

                let _ = writeln!(f);

                let max_key_len = checks_from_env
                    .missing_values
                    .keys()
                    .chain(checks_from_env.missing_default.keys())
                    .chain(checks_from_env.incorrect_values.keys())
                    .chain(checks_from_env.missing_secrets.iter())
                    .chain(checks_from_env.missing_optional.iter())
                    .map(|k| k.len())
                    .max()
                    .unwrap_or(0);

                if !checks_from_env.missing_optional.is_empty() {
                    let _ = writeln!(
                        f,
                        "{}  {} optional variables missing from env:",
                        "Warning:".yellow().bold(),
                        checks_from_env.missing_optional.len(),
                    );
                    for key in checks_from_env.missing_optional.iter() {
                        let _ = writeln!(f, "          {:width$} ", key, width = max_key_len);
                    }
                    let _ = writeln!(f);
                }

                // Incorrect Values
                if !checks_from_env.incorrect_values.is_empty() {
                    let _ = writeln!(
                        f,
                        "{} Variables with incorrect values:",
                        "Error:".red().bold()
                    );
                }
                for (key, incorrect_value) in checks_from_env.incorrect_values.iter() {
                    let _ = writeln!(
                        f,
                        "          {:width$}: '{}'",
                        key,
                        truncated(incorrect_value),
                        width = max_key_len
                    );
                }
                if !checks_from_env.incorrect_values.is_empty() {
                    let _ = writeln!(f);
                }

                if total_missing > 0 {
                    let _ = writeln!(
                        f,
                        "{}    {} {}",
                        "Error:".red().bold(),
                        total_missing.to_string().bold(),
                        "required variables missing from env:".bold(),
                    );
                }
                for (key, missing_value) in checks_from_env.missing_values.iter() {
                    let _ = writeln!(
                        f,
                        "(value)   {:width$}: '{}'",
                        key,
                        truncated(missing_value),
                        width = max_key_len
                    );
                }
                for (key, missing_value) in checks_from_env.missing_default.iter() {
                    let _ = writeln!(
                        f,
                        "(default) {:width$}: '{}'",
                        key,
                        truncated(missing_value),
                        width = max_key_len
                    );
                }
                for key in checks_from_env.missing_secrets.iter() {
                    let _ = writeln!(f, "(secret)  {:width$}", key, width = max_key_len);
                }

                write!(f, "")
            }
        }
    }
}

impl ShieldResponse {
    pub fn new(filename: &str) -> ShieldResponse {
        let schema = match FinalizedSchema::new(filename) {
            Ok(s) => s,
            Err(err) => match err {
                ShieldError::Unrecoverable(err) => {
                    return Self {
                        status: ShieldStatus::Hopeless,
                        schema_file: filename.to_string(),
                        kind: ShieldResponseKind::Failed {
                            error: err.to_string(),
                        },
                    };
                }
                _ => {
                    return Self {
                        status: ShieldStatus::Recoverable,
                        schema_file: filename.to_string(),
                        kind: ShieldResponseKind::Failed {
                            error: err.to_string(),
                        },
                    };
                }
            },
        };

        // Compare schema requirements with what is in the environment
        let env_vars: EnvMap = std::env::vars().collect();
        let checked_from_env = SchemaCheck::new(&schema, &env_vars);

        Self {
            status: ShieldStatus::Operational,
            schema_file: filename.to_string(),
            kind: ShieldResponseKind::Success {
                checks_from_env: Box::new(checked_from_env),
            },
        }
    }
}

use test_generator::test_resources;

#[allow(unused)]
#[test_resources("test-files/invalid/*.toml")]
fn invalid_test(filename: &str) {
    assert!(std::path::Path::new(filename).exists());

    let response = ShieldResponse::new(filename);

    assert!(matches!(
        response.kind,
        ShieldResponseKind::Failed { error: _ }
    ));
}

#[allow(unused)]
#[test_resources("test-files/valid/*.toml")]
fn valid_test(filename: &str) {
    assert!(std::path::Path::new(filename).exists());

    let response = ShieldResponse::new(filename);

    assert!(matches!(
        response.kind,
        ShieldResponseKind::Success { checks_from_env: _ }
    ));
}

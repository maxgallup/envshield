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

use clap::Parser;
use colored::Colorize;
use std::collections::HashMap;
use std::fmt::Display;

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

mod error;
use error::ShieldError;
mod node;
use node::{Node, ResolvedNode, StringChunk, UnresolvedNode, extract_string_chunks};
mod log;

/// The main schema file that is read into memory
const MAX_DISPLAY_LEN: usize = 50;

type EnvMap = HashMap<String, String>;

/// Tries to resolve the first unresolved node in the list. If successful, it will remove it from
/// the unresolved list and add it to the resolved list. If not successful, returns false.
fn try_to_resolve(
    unresolved: &mut Vec<UnresolvedNode>,
    resolved: &mut Vec<ResolvedNode>,
) -> Result<(), ShieldError> {
    let unresolved_node_opt = unresolved.first_mut();

    if let Some(unresolved_node) = unresolved_node_opt {
        let available: HashMap<&String, &String> =
            resolved.iter().map(|r| (&r.key, &r.value)).collect();

        let resolved_string_chunks: Vec<String> = unresolved_node
            .chunks
            .iter()
            .map(|chunk| match chunk {
                StringChunk::Original(s) => Ok(s.to_string().clone()),
                StringChunk::Reference(r) => {
                    if let Some(resolved) = available.get(r) {
                        Ok(resolved.to_string().clone())
                    } else {
                        info!("    -- couldn't resolve {}", r);
                        unresolved_node.offending_node = Some(r.clone());
                        Err(ShieldError::UnresolvedReference)
                    }
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let resolved_string: String = resolved_string_chunks.join("");
        info!("    >> resolved {}", unresolved_node.key);
        // Add the newly resolved node to the existing ones
        resolved.push(ResolvedNode {
            key: unresolved_node.key.clone(),
            value: resolved_string,
        });

        // Remove the unresolved one from the list - this will always be the first one
        // since that what this function does.
        unresolved.remove(0);

        return Ok(());
    }

    Err(ShieldError::UnresolvedReference)
}

/// Describes semantically valid schemas but with unresolved references
#[derive(Debug, Clone, Serialize)]
enum ValidatedSchema {
    Version1(HashMap<String, ValidatedAttribute>),
}

impl TryFrom<ParsedSchema> for ValidatedSchema {
    type Error = ShieldError;

    fn try_from(value: ParsedSchema) -> Result<ValidatedSchema, ShieldError> {
        let validated = match value {
            ParsedSchema::Version1(hash_map) => {
                // Check that only allowed combinations of options are possible
                hash_map
                    .into_iter()
                    .map(|(key, attr)| {
                        if attr.value.is_none() && attr.default.is_none() && attr.optional.is_none()
                        {
                            return Ok((
                                key,
                                ValidatedAttribute {
                                    description: attr.description,
                                    options: ValidatedOptions::Secret,
                                },
                            ));
                        }

                        if let Some(default) = attr.default.clone()
                            && attr.optional.is_none()
                            && attr.value.is_none()
                        {
                            return Ok((
                                key,
                                ValidatedAttribute {
                                    description: attr.description,
                                    options: ValidatedOptions::WithDefault(default),
                                },
                            ));
                        };

                        if let Some(option) = attr.optional
                            && attr.default.is_none()
                            && attr.value.is_none()
                        {
                            if option {
                                return Ok((
                                    key,
                                    ValidatedAttribute {
                                        description: attr.description,
                                        options: ValidatedOptions::Optional,
                                    },
                                ));
                            } else {
                                return Err(ShieldError::InvalidSchema(
                                    "'optional' can only be set to true".to_string(),
                                ));
                            }
                        }

                        if let Some(value) = attr.value.clone()
                            && attr.default.is_none()
                            && attr.optional.is_none()
                        {
                            return Ok((
                                key,
                                ValidatedAttribute {
                                    description: attr.description,
                                    options: ValidatedOptions::WithValue(value),
                                },
                            ));
                        }

                        Err(ShieldError::InvalidSchema(format!(
                            "illegal combination of options for variable [{}]",
                            key
                        )))
                    })
                    .collect::<Result<HashMap<_, _>, _>>()?
            }
        };

        Ok(ValidatedSchema::Version1(validated))
    }
}

/// Describes valid schemas with resolved references
#[derive(Debug, Serialize)]
enum FinalizedSchema {
    Version1(HashMap<String, ValidatedAttribute>),
}

/// This type is used to hold all information necessary to report back to the user
/// about the mismatch from the schema to their current environment.
#[derive(Debug, Deserialize, Serialize)]
struct SchemaCheck {
    /// The subset from the schema that was correctly implemented in the environment. There
    /// are no errors or warnings, when this subset covers the set from the schema entirely.
    existing_subset: EnvMap,
    /// This set contains the variables that were marked with values, but the values don't match.
    incorrect_values: EnvMap,
    /// This is the set of variables marked as values that don't exist in the env.
    missing_values: EnvMap,
    /// This set contains defaults set in the schema that aren't set in the environment.
    missing_default: EnvMap,
    /// This set contains options set in the schema that aren't set in the environment.
    missing_optional: Vec<String>,
    /// This set contains secrets set in the schema that aren't set in the environment.
    missing_secrets: Vec<String>,
    /// Set of keys in env that are not in the schema
    not_in_schema: Vec<String>,
}

impl SchemaCheck {
    fn new(final_schema: &FinalizedSchema, env_map: &EnvMap) -> Self {
        let mut result = SchemaCheck {
            existing_subset: HashMap::new(),
            incorrect_values: HashMap::new(),
            missing_default: HashMap::new(),
            missing_values: HashMap::new(),
            missing_optional: Vec::new(),
            missing_secrets: Vec::new(),
            not_in_schema: Vec::new(),
        };

        match final_schema {
            FinalizedSchema::Version1(schema_map) => {
                // Fill the result struct with the necessary data
                for (schema_key, validated_attribute) in schema_map.iter() {
                    if let Some((_, env_value)) =
                        env_map.iter().find(|(b_key, _)| b_key == &schema_key)
                    {
                        // Fill the existing subset Map
                        result
                            .existing_subset
                            .insert(schema_key.clone(), env_value.clone());
                    } else {
                        // Value is missing, what kind is it?
                        match &validated_attribute.options {
                            ValidatedOptions::Optional => {
                                result.missing_optional.push(schema_key.clone())
                            }
                            ValidatedOptions::Secret => {
                                result.missing_secrets.push(schema_key.clone())
                            }
                            ValidatedOptions::WithValue(value) => {
                                result
                                    .missing_values
                                    .insert(schema_key.clone(), value.clone());
                            }
                            ValidatedOptions::WithDefault(default) => {
                                result
                                    .missing_default
                                    .insert(schema_key.clone(), default.clone());
                            }
                        }
                    }

                    // Check for any incorrect values
                    let matching_entry = env_map.iter().find(|(env_key, _)| env_key == &schema_key);
                    if let Some((_, matching_value)) = matching_entry
                        && let ValidatedOptions::WithValue(expected_value) =
                            &validated_attribute.options
                        && expected_value != matching_value
                    {
                        result
                            .incorrect_values
                            .insert(schema_key.clone(), expected_value.clone());
                    }
                }

                // Check for superfluous variables
                for env_key in env_map.keys() {
                    if !schema_map.contains_key(env_key) {
                        result.not_in_schema.push(env_key.clone());
                    }
                }
            }
        }

        result
    }
}

impl TryFrom<ValidatedSchema> for FinalizedSchema {
    type Error = ShieldError;

    fn try_from(value: ValidatedSchema) -> Result<FinalizedSchema, ShieldError> {
        match value {
            ValidatedSchema::Version1(hash_map) => {
                let mut result = hash_map.clone();
                // We start by looking at all of the variables that have no references in their value
                // or in their default section
                let nodes: Vec<Node> = result
                    .clone()
                    .into_iter()
                    .map(|(key, attr)| match &attr.options {
                        ValidatedOptions::WithValue(input_string)
                        | ValidatedOptions::WithDefault(input_string) => {
                            let string_chunks = extract_string_chunks(&key, input_string)?;
                            let contains_references = string_chunks
                                .iter()
                                .any(|chunk| matches!(chunk, StringChunk::Reference(_)));

                            if contains_references {
                                Ok(Some(Node::Unresolved(UnresolvedNode {
                                    key,
                                    chunks: string_chunks,
                                    offending_node: None,
                                })))
                            } else {
                                Ok(Some(Node::Resolved(ResolvedNode {
                                    key,
                                    value: input_string.clone(),
                                })))
                            }
                        }
                        _ => Ok(None),
                    })
                    .collect::<Result<Vec<Option<Node>>, ShieldError>>()?
                    .into_iter()
                    .flatten()
                    .collect();

                let mut resolved: Vec<ResolvedNode> = nodes
                    .clone()
                    .into_iter()
                    .filter_map(|node| {
                        if let Node::Resolved(root) = node {
                            Some(root)
                        } else {
                            None
                        }
                    })
                    .collect();

                let mut unresolved: Vec<UnresolvedNode> = nodes
                    .into_iter()
                    .filter_map(|node| {
                        if let Node::Unresolved(child) = node {
                            Some(child)
                        } else {
                            None
                        }
                    })
                    .collect();

                let dead_ends: HashMap<&String, &ValidatedAttribute> = hash_map
                    .iter()
                    .filter(|(key, _)| {
                        let not_resolved = resolved
                            .iter()
                            .all(|resolved_node| &resolved_node.key != *key);

                        let not_unresolved = unresolved
                            .iter()
                            .all(|unresolved_node| &unresolved_node.key != *key);

                        not_resolved && not_unresolved
                    })
                    .collect();

                // Quick check to see if any of the references in the unresolved
                // don't exist in the resolved keys, then we can exit early
                for unresolved_node in unresolved.iter() {
                    for chunk in unresolved_node.chunks.iter() {
                        match chunk {
                            StringChunk::Original(_) => (),
                            StringChunk::Reference(r) => {
                                // If there is a reference to a Node that can't be resolved,
                                // exit early.
                                if dead_ends.contains_key(r) {
                                    return Err(ShieldError::DeadEndReference(
                                        unresolved_node.key.clone(),
                                        r.clone(),
                                    ));
                                }

                                if !result.contains_key(r) {
                                    return Err(ShieldError::MissingReferenceExtended(
                                        unresolved_node.key.clone(),
                                        r.clone(),
                                    ));
                                }

                                if &unresolved_node.key == r {
                                    return Err(ShieldError::CyclicReference(r.clone()));
                                }
                            }
                        }
                    }
                }

                let mut stagnation_counter = 0;
                let mut iteration = 0;

                loop {
                    info!(
                        "{} ({}/{})",
                        iteration,
                        stagnation_counter,
                        unresolved.len()
                    );
                    iteration += 1;

                    if unresolved.is_empty() {
                        // No work to do
                        break;
                    }

                    match try_to_resolve(&mut unresolved, &mut resolved) {
                        Ok(_) => {
                            // Reset the counter, since we have made progress.
                            stagnation_counter = 0;
                        }
                        Err(_) => {
                            // Increase the counter, since we did not make progress
                            stagnation_counter += 1;
                        }
                    }

                    if let Some(last) = unresolved.pop() {
                        unresolved.insert(0, last);
                    } else {
                        // We popped the last one, so we are done
                        break;
                    }

                    // If we haven't been making progress for more than twice the number
                    // of unresolved ones we can be sure that there is either a loop, or there
                    // is a reference to a node that can't be resolved.
                    // TODO: check for that case earlier
                    if stagnation_counter > (2 * unresolved.len()) && !unresolved.is_empty() {
                        if let Some(missing) = unresolved.first() {
                            error!("total unresolved: {}", unresolved.len());
                            if let Some(offender) = &missing.offending_node {
                                return Err(ShieldError::MissingReferenceExtended(
                                    missing.key.clone(),
                                    offender.clone(),
                                ));
                            } else {
                                return Err(ShieldError::MissingReference(missing.key.clone()));
                            }
                        } else {
                            error!("expected to see at least one unresolved node, but didn't");
                        }
                    }
                }

                info!("all references resolved");

                for (key, validated_attr) in result.iter_mut() {
                    if let Some(resolved_node) = resolved.iter().find(|node| &node.key == key) {
                        match validated_attr.options {
                            ValidatedOptions::WithValue(ref mut value) => {
                                *value = resolved_node.value.clone();
                            }
                            ValidatedOptions::WithDefault(ref mut description) => {
                                *description = resolved_node.value.clone();
                            }
                            _ => (),
                        }
                    }
                }

                Ok(FinalizedSchema::Version1(result))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct ValidatedAttribute {
    description: String,
    options: ValidatedOptions,
}

#[derive(Debug, Clone, Serialize)]
enum ValidatedOptions {
    /// Variable does not have to be set, but can be.
    Optional,
    /// Such an attribute indicates that the key simply must exist and defined by the user.
    /// This likely indicates that it is a secret and should not be pushed to git.
    Secret,
    /// Indicates what provided value the env variable will have and enforces this.
    WithValue(String),
    /// Suggests a default for what a variable should be, but won't be enforced.
    WithDefault(String),
}

/// This type is used for having parsing out valid toml files, however the data in this type is
/// not per se semantically valid. For that, we have `Validated`.
#[derive(Debug, Deserialize)]
#[serde(tag = "version")]
#[serde(deny_unknown_fields)]
enum ParsedSchema {
    #[serde(rename = "1")]
    Version1(HashMap<String, Attributes>),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attributes {
    #[serde(deserialize_with = "validate_description")]
    description: String,

    value: Option<String>,

    optional: Option<bool>,

    default: Option<String>,
}

fn validate_description<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    // TODO: add proper sentence validation
    if s.is_empty() {
        Err(de::Error::custom("host cannot be empty"))
    } else {
        Ok(s)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum ShieldStatus {
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
struct ShieldResponse {
    schema_file: String,
    status: ShieldStatus,
    kind: ShieldResponseKind,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum ShieldResponseKind {
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

                    if total_missing == 0 && checks_from_env.missing_optional.is_empty() {
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

impl FinalizedSchema {
    fn new(filename: &str) -> Result<FinalizedSchema, ShieldError> {
        info!("reading: {}", filename);
        let schema_contents = std::fs::read_to_string(filename)?;

        info!("parsing {} into ShieldSchema", filename);
        let parsed: ParsedSchema = toml::from_str(&schema_contents)?;

        info!("validating schema");
        let validated_schema = ValidatedSchema::try_from(parsed)?;

        info!("resolving references");
        let finalized_schema = FinalizedSchema::try_from(validated_schema)?;

        Ok(finalized_schema)
    }
}

impl ShieldResponse {
    fn new(filename: &str) -> ShieldResponse {
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

use std::collections::HashMap;
use std::fmt::Display;

use clap::Parser;

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

mod error;
use error::ShieldError;
mod node;
use node::{Node, ResolvedNode, StringChunk, UnresolvedNode, extract_string_chunks};
mod log;

/// The main schema file that is read into memory
const SCHEMA_FILENAME: &str = "env.toml";

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

    return Err(ShieldError::UnresolvedReference);
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
                                    options: ValidatedOptions::DescriptionOnly,
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

                        if let Some(option) = attr.optional.clone()
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
                                return Err(ShieldError::InvalidSchema(format!(
                                    "'optional' can only be set to true"
                                )));
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

                        return Err(ShieldError::InvalidSchema(format!(
                            "illegal combination of options for variable [{}]",
                            key
                        )));
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
                            let string_chunks = extract_string_chunks(&key, &input_string)?;
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
                    iteration = iteration + 1;

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
                            stagnation_counter = stagnation_counter + 1;
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
    DescriptionOnly,
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
#[serde(untagged)]
enum ShieldResponse {
    Failed {
        status: ShieldStatus,
        error: String, // this should include the data from the custom Error type's Display impl
    },
    Success {
        status: ShieldStatus,
        data: serde_json::Value,
    },
}

impl Display for ShieldResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShieldResponse::Failed { status, error } => {
                let _ = writeln!(f, "Status: {:?}", status);
                write!(f, "{}", error)
            }
            ShieldResponse::Success { status, data } => {
                let _ = writeln!(f, "Status: {:?}", status);
                write!(f, "{:#?}", data)
            }
        }
    }
}

impl FinalizedSchema {
    fn new() -> Result<FinalizedSchema, ShieldError> {
        info!("reading: {}", SCHEMA_FILENAME);
        let schema_contents = std::fs::read_to_string(SCHEMA_FILENAME)?;

        info!("parsing {} into ShieldSchema", SCHEMA_FILENAME);
        let parsed: ParsedSchema = toml::from_str(&schema_contents)?;

        info!("validating schema");
        let validated_schema = ValidatedSchema::try_from(parsed)?;

        info!("resolving references");
        let finalized_schema = FinalizedSchema::try_from(validated_schema)?;

        Ok(finalized_schema)
    }
}

impl ShieldResponse {
    fn new() -> ShieldResponse {
        let schema = match FinalizedSchema::new() {
            Ok(s) => s,
            Err(err) => match err {
                ShieldError::Unrecoverable(err) => {
                    return Self::Failed {
                        status: ShieldStatus::Hopeless,
                        error: format!("{}", err),
                    };
                }
                _ => {
                    return Self::Failed {
                        status: ShieldStatus::Recoverable,
                        error: format!("{}", err),
                    };
                }
            },
        };

        Self::Success {
            status: ShieldStatus::Operational,
            data: serde_json::to_value(schema).unwrap(),
        }
    }
}

/// Program that does some basic schema checking for the environment file
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct InputArgs {
    /// Output will be in json format to be machine readable
    #[arg(short, long, default_value_t = false)]
    json: bool,
}

fn main() {
    let args = InputArgs::parse();

    // let env_data: HashMap<String, String> = dotenv::vars().collect();

    // /// We keep track of the environment variables that are missing and distinguish
    // /// them based on whether they're required or optional
    // let missing_required: Vec<String> = vec![];
    // let missing_optional: Vec<String> = vec![];

    // // for (key, value) in env_file.iter() {
    // //     dbg!(key, value);
    // //     if key == "asdf" {

    // //     }
    // // }

    // // For each entry in the schema, make sure that it exists in the environment
    // // if it doesn't add it to the env file.
    // for (key, data) in config.0.iter() {
    //     if let Some(optional) = data.optional {}

    //     if !env_data.contains_key(key) {
    //         println!("missing: {}", key);
    //     }
    // }

    let response = ShieldResponse::new();

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
        println!("{}", response);
    }
}

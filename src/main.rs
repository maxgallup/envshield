use std::collections::HashMap;
use std::fmt::{self, Display};

use clap::Parser;
use dotenv;

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

mod log;

/// The main schema file that is read into memory
const SCHEMA_FILENAME: &str = "env.toml";

/// Node type used to find reference dependency chains
#[derive(Debug, Clone)]
enum Node {
    /// These nodes are pointed to by other reference Nodes
    Resolved(ResolvedNode),
    /// When None, this is a root node with no dependencies
    Unresolved(UnresolvedNode),
}

#[derive(Debug, Clone)]
struct ResolvedNode {
    key: String,
    value: String,
}

#[derive(Debug, Clone)]
struct UnresolvedNode {
    key: String,
    chunks: Vec<StringChunk>,
    offending_node: Option<String>,
}

#[derive(Debug, Clone)]
enum StringChunk {
    Original(String),
    Reference(String),
}

/// Returns a chopped up version of the original string where each reference is denoted marked.
fn extract_string_chunks(
    key: &String,
    input_string: &String,
) -> Result<Vec<StringChunk>, ShieldError> {
    let start_delimiter = "{{";
    let end_delimiter = "}}";

    let mut result: Vec<StringChunk> = vec![];
    let mut processed_string: &str = &input_string;

    // 1. Start by finding match of starting delimiter
    loop {
        // If we can't find the starting delimiter it, then there either never was one to begin
        // with or we're done processing!
        let Some(start_delim_index) = processed_string.find(start_delimiter) else {
            let string_part = &processed_string[..].to_string();
            result.push(StringChunk::Original(string_part.clone()));
            break;
        };

        if start_delim_index >= processed_string.len() {
            return Err(ShieldError::ReferenceParsing(format!(
                "position of starting delimiter '{}' (index: {}) out of string bounds!",
                start_delimiter, start_delim_index
            )));
        };

        let name_start = start_delim_index + start_delimiter.len();
        let Some(end_delim_offset) = &processed_string[name_start..].find(end_delimiter) else {
            return Err(ShieldError::ReferenceParsing(format!(
                "key [{}] is missing closing delimiter '{}'",
                key, end_delimiter
            )));
        };

        let name_end = name_start + end_delim_offset;
        let string_part = &processed_string[..start_delim_index].to_string();
        let reference_name = &processed_string[name_start..name_end].trim().to_string();

        if reference_name.contains("{") || reference_name.contains("}") {
            return Err(ShieldError::ReferenceParsing(format!(
                "key [{}] has a reference with nested brackets",
                key
            )));
        }

        if !string_part.is_empty() {
            result.push(StringChunk::Original(string_part.clone()))
        }

        if !reference_name.is_empty() {
            result.push(StringChunk::Reference(reference_name.clone()))
        }
        processed_string = &processed_string[(name_end + end_delimiter.len())..];
    }

    Ok(result)
}

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

        info!("------------------------------------------------");
        info!("attempting to resolve {:#?}", unresolved_node);
        info!("with these nodes available: {:#?}", available);
        let resolved_string_chunks: Vec<String> = unresolved_node
            .chunks
            .iter()
            .map(|chunk| match chunk {
                StringChunk::Original(s) => Ok(s.to_string().clone()),
                StringChunk::Reference(r) => {
                    if let Some(resolved) = available.get(r) {
                        Ok(resolved.to_string().clone())
                    } else {
                        warn!("could not resolve: {}", r);
                        unresolved_node.offending_node = Some(r.clone());
                        Err(ShieldError::UnresolvedReference)
                    }
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let resolved_string: String = resolved_string_chunks.join("");
        info!(">> resolved string:");
        info!("       '{}'", resolved_string);

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

/// Describes semantically valid schemas
#[derive(Debug, Serialize)]
enum ValidatedSchema {
    Version1(HashMap<String, ValidatedAttribute>),
}

impl TryFrom<ParsedSchema> for ValidatedSchema {
    type Error = ShieldError;

    fn try_from(value: ParsedSchema) -> Result<Self, ShieldError> {
        let raw_config = match value {
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

        raw_config
            .clone()
            .into_iter()
            .for_each(|(key, attr)| match &attr.options {
                ValidatedOptions::WithValue(value) | ValidatedOptions::WithDefault(value) => {
                    let _ = extract_string_chunks(&key, value);
                }
                _ => (),
            });

        // We start by looking at all of the variables that have no references in their value
        // or in their default section
        let nodes: Vec<Node> = raw_config
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

        info!("{:#?}", resolved);
        info!("{:#?}", unresolved);

        let mut num_unresolved = unresolved.len();
        let mut stagnation_counter = 0;

        loop {
            num_unresolved = unresolved.len();

            if !unresolved.is_empty() {
                match try_to_resolve(&mut unresolved, &mut resolved) {
                    Ok(_) => {
                        info!("made progress!");
                        stagnation_counter = 0;
                    }
                    Err(e) => {
                        warn!("did not make progress");
                    }
                }

                if let Some(last) = unresolved.pop() {
                    unresolved.insert(0, last);
                } else {
                    break;
                }
            }

            if unresolved.is_empty() {
                info!("empty, leaving");
                break;
            }

            if num_unresolved == unresolved.len() {
                stagnation_counter = stagnation_counter + 1;
                error!("setting sc to {}", stagnation_counter);
            }

            if stagnation_counter == (10 * unresolved.len()) {
                let unresolved_node_opt = unresolved.first();
                if let Some(missing) = unresolved_node_opt {
                    error!("sc, {}", stagnation_counter);
                    error!("total {} unresolved: {:#?}", unresolved.len(), unresolved);
                    if let Some(offender) = &missing.offending_node {
                        return Err(ShieldError::MissingReferenceExtended(
                            missing.key.clone(),
                            offender.clone(),
                        ));
                    } else {
                        return Err(ShieldError::MissingReference(missing.key.clone()));
                    }
                }
            }
        }

        info!("FINISHED");
        info!("{:#?}", resolved);

        // 1. While there are unresolved nodes, pick an unresolved node and attempt to resolve it
        // 2. if success, remove it from unresolved nodes and put it into resolved nodes
        // 3. if fail, try the next node.

        // for child in children.iter() {
        //     for parent in child.parents.iter() {

        //         if parent == &child.key {
        //             return Err(ShieldError::CyclicReference(parent.clone()));
        //         }

        //         let valid_destinations =
        //         // for potential_node in nodes.iter() {
        //         //     match potential_node {
        //         //         RefNode::Root(RootNode { key: root_key }) => {
        //         //             if
        //         //         },
        //         //         RefNode::Child(ChildNode { key: child_key, _ }) => todo!(),
        //         //     }
        //         // }
        //     }

        //     // for parent in node_parents.iter() {
        //     //     for ref_node in nodes.iter() {
        //     //         // match ref_node {
        //     //         //     RefNode::Root { key: ref_key } => {
        //     //         //         if node_key == ref_key {
        //     //         //             return Err(ShieldError::CyclicReference(ref_key.clone()));
        //     //         //         }
        //     //         //     }
        //     //         //     RefNode::Child { key: child_key, parents } => {
        //     //         //         if node_key ==
        //     //         //     },
        //     //         // }

        //     //         // if key == ref_node {
        //     //         //     return Err(ShieldError::MissingReference());
        //     //         // }
        //     //     }

        //     //     if !raw_config.contains_key(parent) {
        //     //         return Err(ShieldError::MissingReference(key.clone(), parent.clone()));
        //     //     }
        //     // }
        // }

        // let a: Vec<(&str, Vec<&str>)> = non_roots
        //     .into_iter()
        //     .flat_map(|non_root| {
        //         if let Some(parents) = &non_root.parents {
        //             Some((
        //                 non_root.key,
        //                 parents
        //                     .into_iter()
        //                     .filter(|reference| !raw_config.contains_key(reference.clone()))
        //                     .collect::<Vec<&str>>(),
        //             ))
        //         } else {
        //             None
        //         }
        //     })
        //     .collect();

        Ok(ValidatedSchema::Version1(raw_config))
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

#[derive(Debug, Deserialize, Serialize, thiserror::Error)]
enum ShieldError {
    #[error("unresolved reference")]
    UnresolvedReference,

    #[error("key [{0}] contains a reference which points to itself")]
    CyclicReference(String),

    #[error("key [{0}] contains a reference that doesn't exist")]
    MissingReference(String),

    #[error("key [{0}] contains reference '{1}' that doesn't exist")]
    MissingReferenceExtended(String, String),

    #[error("parsing reference: {0}")]
    ReferenceParsing(String),

    #[error("with schema '.env.toml': {0}")]
    Unrecoverable(String),

    #[error("could not find schema '.env.toml': {0}")]
    MissingSchema(String),

    #[error("invalid schema: {0}")]
    InvalidSchema(String),

    #[error("toml validation: {0}")]
    TomlValidation(String),
}

impl From<std::io::Error> for ShieldError {
    fn from(value: std::io::Error) -> Self {
        match value.kind() {
            std::io::ErrorKind::NotFound => ShieldError::MissingSchema(value.to_string()),
            _ => ShieldError::Unrecoverable(value.to_string()),
        }
    }
}

impl From<toml::de::Error> for ShieldError {
    fn from(value: toml::de::Error) -> Self {
        ShieldError::TomlValidation(value.to_string())
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

impl ValidatedSchema {
    fn new() -> Result<ValidatedSchema, ShieldError> {
        info!("reading: {}", SCHEMA_FILENAME);
        let schema_contents = std::fs::read_to_string(SCHEMA_FILENAME)?;

        info!("parsing {} into ShieldSchema", SCHEMA_FILENAME);
        let parsed: ParsedSchema = toml::from_str(&schema_contents)?;

        info!("validating schema");
        let validated_schema = ValidatedSchema::try_from(parsed)?;

        Ok(validated_schema)
    }
}

impl ShieldResponse {
    fn new() -> ShieldResponse {
        let schema = match ValidatedSchema::new() {
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

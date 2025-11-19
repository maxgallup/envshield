use std::collections::HashMap;
use std::fmt::{self, Display};

use clap::Parser;
use dotenv;
use miette::{Diagnostic, LabeledSpan, MietteHandler, ReportHandler};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

mod log;

/// The main schema file that is read into memory
const SCHEMA_FILENAME: &str = "env.toml";

struct Node {
    /// The environment variable
    key: String,
    /// When None, this is a root node with no dependencies
    parent: Option<String>,
}

/// Describes semantically valid schemas
#[derive(Debug, Serialize)]
enum ValidatedSchema {
    Version1(HashMap<String, ValidatedAttribute>),
}

impl TryFrom<ParsedSchema> for ValidatedSchema {
    type Error = ShieldError;

    fn try_from(value: ParsedSchema) -> Result<Self, ShieldError> {
        let hash_map = match value {
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

        Ok(ValidatedSchema::Version1(hash_map))
    }
}

#[derive(Debug, Serialize)]
struct ValidatedAttribute {
    description: String,
    options: ValidatedOptions,
}

#[derive(Debug, Serialize)]
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
    #[error("error with schema '.env.toml': {0}")]
    SchemaError(String),

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
            _ => ShieldError::SchemaError(value.to_string()),
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
            Err(err) => {
                return Self::Failed {
                    status: ShieldStatus::Recoverable,
                    error: format!("{}", err),
                };
            }
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

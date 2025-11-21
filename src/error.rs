use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, thiserror::Error)]
pub enum ShieldError {
    #[error("unresolved reference")]
    UnresolvedReference,

    #[error("key [{0}] contains a reference which points to itself")]
    CyclicReference(String),

    #[error("key [{0}] contains a reference that doesn't exist")]
    MissingReference(String),

    #[error("key [{0}] contains reference '{1}' that doesn't exist")]
    MissingReferenceExtended(String, String),

    #[error("key [{0}] contains a reference to '{1}', but '{1}' can't resolve that reference")]
    DeadEndReference(String, String),

    #[error("parsing: {0}")]
    ReferenceParsing(String),

    #[error("with schema: {0}")]
    Unrecoverable(String),

    #[error("could not find schema file: {0}")]
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

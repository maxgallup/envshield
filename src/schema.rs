use crate::{
    ShieldError, error, info,
    node::{Node, ResolvedNode, StringChunk, UnresolvedNode, extract_string_chunks},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type EnvMap = HashMap<String, String>;

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
pub enum FinalizedSchema {
    Version1(HashMap<String, ValidatedAttribute>),
}

impl FinalizedSchema {
    pub fn new(filename: &str) -> Result<FinalizedSchema, ShieldError> {
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

/// This type is used to hold all information necessary to report back to the user
/// about the mismatch from the schema to their current environment.
#[derive(Debug, Deserialize, Serialize)]
pub struct SchemaCheck {
    /// The subset from the schema that was correctly implemented in the environment. There
    /// are no errors or warnings, when this subset covers the set from the schema entirely.
    pub existing_subset: EnvMap,
    /// This set contains the variables that were marked with values, but the values don't match.
    pub incorrect_values: EnvMap,
    /// This is the set of variables marked as values that don't exist in the env.
    pub missing_values: EnvMap,
    /// This set contains defaults set in the schema that aren't set in the environment.
    pub missing_default: EnvMap,
    /// This set contains options set in the schema that aren't set in the environment.
    pub missing_optional: Vec<String>,
    /// This set contains secrets set in the schema that aren't set in the environment.
    pub missing_secrets: Vec<String>,
    /// Set of keys in env that are not in the schema
    pub not_in_schema: Vec<String>,
}

impl SchemaCheck {
    pub fn new(final_schema: &FinalizedSchema, env_map: &EnvMap) -> Self {
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
pub struct ValidatedAttribute {
    pub description: String,
    pub options: ValidatedOptions,
}

#[derive(Debug, Clone, Serialize)]
pub enum ValidatedOptions {
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
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    // TODO: add proper sentence validation
    if s.is_empty() {
        Err(serde::de::Error::custom("host cannot be empty"))
    } else {
        Ok(s)
    }
}

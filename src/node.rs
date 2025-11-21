use crate::error::ShieldError;

/// Node type used to find reference dependency chains
#[derive(Debug, Clone)]
pub enum Node {
    /// These nodes are pointed to by other reference Nodes
    Resolved(ResolvedNode),
    /// When None, this is a root node with no dependencies
    Unresolved(UnresolvedNode),
}

#[derive(Debug, Clone)]
pub struct ResolvedNode {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct UnresolvedNode {
    pub key: String,
    pub chunks: Vec<StringChunk>,
    pub offending_node: Option<String>,
}

#[derive(Debug, Clone)]
pub enum StringChunk {
    Original(String),
    Reference(String),
}

/// Returns a chopped up version of the original string where each reference is denoted marked.
pub fn extract_string_chunks(
    key: &String,
    input_string: &String,
) -> Result<Vec<StringChunk>, ShieldError> {
    let start_delimiter = "{{";
    let end_delimiter = "}}";

    let mut result: Vec<StringChunk> = vec![];
    let mut processed_string: &str = input_string;

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

        if reference_name.is_empty() {
            return Err(ShieldError::ReferenceParsing(format!(
                "key [{}] has an empty reference",
                key
            )));
        }

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

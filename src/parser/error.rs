use thiserror;

/// Custom Error Type
#[derive(thiserror::Error, Debug)]
pub enum DocumentParseError {
    #[error("an internal parsing error occured (raised by nom)")]
    Internal(#[from] nom::error::Error<String>),
    #[error("Parsing stopped after {index} characters before input was complete (line {line}, character {character})")]
    InputRemaining {
        index: usize,
        line: usize,
        character: usize,
    },
}

impl DocumentParseError {
    /// Create a new error of variant `InputRemaining`, based on the
    /// observed parser inputs.
    pub fn remaining(total_input: &str, remaining_input: &str) -> DocumentParseError {
        if remaining_input.len() > total_input.len() {
            panic!(
                "More input remaining ({}) than was available before parsing ({}) of Tor document.",
                remaining_input.len(),
                total_input.len()
            );
        }
        let consumed = total_input.len() - remaining_input.len();
        let line = total_input[..consumed].matches('\n').count() + 1;
        let character = match total_input[..consumed].rfind('\n') {
            Some(index) => consumed - index,
            None => consumed + 1,
        };
        DocumentParseError::InputRemaining {
            index: consumed,
            line,
            character,
        }
    }
}

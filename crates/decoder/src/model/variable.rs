//! The value shape [`crate::SemanticDecoder::locals_at`] returns.

/// One local variable visible at a [`super::LogicalFrame`].
///
/// Kept string-based for now rather than a typed value tree: a proper
/// typed representation needs DWARF type info the decoder crate does not
/// own (that lives in the query/introspection engine, Layer 5). This is
/// deliberately the simplest honest shape — expand to a typed `Value` enum
/// only when a consumer (locals rendering, watchpoints) actually needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variable {
    /// The variable's name in source.
    pub name: String,
    /// A rendered representation of its current value.
    pub value: String,
    /// An optional type name/hint for display, when known.
    pub type_hint: Option<String>,
}

impl Variable {
    /// Build a variable with no type hint.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            type_hint: None,
        }
    }

    /// Build a variable with an explicit type hint.
    #[must_use]
    pub fn with_type(
        name: impl Into<String>,
        value: impl Into<String>,
        type_hint: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            type_hint: Some(type_hint.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_has_no_type_hint() {
        let var = Variable::new("x", "42");
        assert_eq!(var.type_hint, None);
    }

    #[test]
    fn with_type_carries_hint() {
        let var = Variable::with_type("x", "42", "i32");
        assert_eq!(var.type_hint.as_deref(), Some("i32"));
    }
}

//! The resolved layout of one rustc-generated `async fn` coroutine, plus the
//! registry of all such layouts in a target binary.
//!
//! This is the portable, DWARF-free heart of the decoder: [`super::dwarf`]
//! produces these structs from a binary's `DW_TAG_variant_part`s, and
//! [`super::decode`] walks them over a [`crate::ProcessView`]. Because a
//! layout is plain data, the decode logic is fully unit-testable on any host
//! with synthetic layouts (mirroring the Go decoder's fake-memory tests).
//!
//! Model (rustc's coroutine representation, verified against 1.85.1 DWARF):
//! an `{async_fn_env#N}` is a struct with one `DW_TAG_variant_part`. Its
//! discriminant is an artificial `__state` member; each `DW_TAG_variant`
//! (`Unresumed`=0, `Returned`=1, `Panicked`=2, `Suspend0`=3, `Suspend1`=4, …)
//! holds that state's live locals. A suspend variant's `__awaitee` member is
//! the future currently being awaited — recursing into it rebuilds the
//! logical async backtrace; sibling inline coroutine members model
//! `join!`/`select!` fan-out.

use std::collections::{BTreeMap, HashMap};

use crate::model::SourceLocation;

/// Which of rustc's fixed coroutine states a `DW_TAG_variant` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariantKind {
    /// State 0: constructed but never polled (holds captured args/upvars).
    Unresumed,
    /// The future completed and returned a value.
    Returned,
    /// The future panicked (poisoned).
    Panicked,
    /// Parked at the Nth `.await` point (`Suspend0` = 0, `Suspend1` = 1, …).
    Suspend(u16),
}

impl VariantKind {
    /// Parse the variant's nested struct name (`Unresumed`, `Returned`,
    /// `Panicked`, `SuspendK`) into a [`VariantKind`]. Returns `None` for an
    /// unrecognized name (a producer whose variant naming this decoder has
    /// not validated) so the caller can decline rather than guess.
    #[must_use]
    pub fn from_struct_name(name: &str) -> Option<Self> {
        match name {
            "Unresumed" => Some(Self::Unresumed),
            "Returned" => Some(Self::Returned),
            "Panicked" => Some(Self::Panicked),
            other => other
                .strip_prefix("Suspend")
                .and_then(|n| n.parse::<u16>().ok())
                .map(Self::Suspend),
        }
    }

    /// Whether this variant is a live suspend (`.await`) point.
    #[must_use]
    pub fn is_suspend(self) -> bool {
        matches!(self, Self::Suspend(_))
    }
}

/// A reference from an active variant to a child future stored inline within
/// it: the offset from the coroutine's base and the child's DWARF type name.
/// The type name keys both the recursion into a nested coroutine (looked up in
/// [`AsyncLayouts`]) and the leaf classification when it is not a coroutine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildRef {
    /// Byte offset of the child future from the parent coroutine's base.
    pub offset: u64,
    /// Fully-qualified DWARF type name of the child future.
    pub type_name: String,
}

impl ChildRef {
    /// Construct a child reference.
    #[must_use]
    pub fn new(offset: u64, type_name: impl Into<String>) -> Self {
        Self {
            offset,
            type_name: type_name.into(),
        }
    }
}

/// One variant of a coroutine's state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariantInfo {
    /// Which fixed rustc state this is.
    pub kind: VariantKind,
    /// Source location of the `.await` this suspend variant parks at, from the
    /// variant member's `DW_AT_decl_file`/`DW_AT_decl_line`. `None` for
    /// non-suspend variants or when line info is absent.
    pub await_location: Option<SourceLocation>,
    /// The `__awaitee` member: the future this variant is directly awaiting,
    /// followed to build the logical stack. `None` if the variant awaits
    /// nothing recorded (e.g. a bare `yield`).
    pub awaitee: Option<ChildRef>,
    /// Additional inline child coroutines held by this variant (e.g. the two
    /// branches of a `join!`), for tree fan-out. Excludes [`Self::awaitee`].
    pub children: Vec<ChildRef>,
}

impl VariantInfo {
    /// A non-suspend variant with no children (Unresumed/Returned/Panicked).
    #[must_use]
    pub fn terminal(kind: VariantKind) -> Self {
        Self {
            kind,
            await_location: None,
            awaitee: None,
            children: Vec::new(),
        }
    }
}

/// The resolved layout of one `{async_fn_env#N}` coroutine type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsyncFnLayout {
    /// Fully-qualified type name, e.g. `probe::sleeper::{async_fn_env#0}`.
    pub type_name: String,
    /// Total size of the coroutine struct in bytes.
    pub byte_size: u64,
    /// Byte offset of the artificial `__state` discriminant member.
    pub discr_offset: u64,
    /// Width of the discriminant in bytes (1 for the `u8` tag rustc emits).
    pub discr_size: u8,
    /// Variants keyed by their `DW_AT_discr_value`.
    pub variants: BTreeMap<u64, VariantInfo>,
}

impl AsyncFnLayout {
    /// The variant selected by a discriminant value read from memory, or
    /// `None` if no variant carries that value (a corrupt or misresolved
    /// discriminant).
    #[must_use]
    pub fn variant_for(&self, discr: u64) -> Option<&VariantInfo> {
        self.variants.get(&discr)
    }

    /// A short display name (the innermost path component before the
    /// `{async_fn_env#N}` marker), e.g. `sleeper` for
    /// `probe::sleeper::{async_fn_env#0}`.
    #[must_use]
    pub fn short_name(&self) -> String {
        let head = self
            .type_name
            .split("::{async_fn_env")
            .next()
            .unwrap_or(&self.type_name);
        head.rsplit("::").next().unwrap_or(head).to_string()
    }
}

/// Every async fn coroutine layout recovered from a target binary, keyed by
/// fully-qualified type name so [`super::decode`] can resolve a child future's
/// type name to a nested coroutine (recurse) or fall through to leaf
/// classification.
#[derive(Debug, Clone, Default)]
pub struct AsyncLayouts {
    by_name: HashMap<String, AsyncFnLayout>,
}

impl AsyncLayouts {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a layout, keyed by its type name.
    pub fn insert(&mut self, layout: AsyncFnLayout) {
        self.by_name.insert(layout.type_name.clone(), layout);
    }

    /// Look up a coroutine layout by fully-qualified type name.
    #[must_use]
    pub fn get(&self, type_name: &str) -> Option<&AsyncFnLayout> {
        self.by_name.get(type_name)
    }

    /// Whether a type name refers to a known coroutine (vs a leaf future).
    #[must_use]
    pub fn is_coroutine(&self, type_name: &str) -> bool {
        self.by_name.contains_key(type_name)
    }

    /// Number of coroutine layouts recovered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether no coroutine layouts were recovered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_variant_kinds() {
        assert_eq!(VariantKind::from_struct_name("Unresumed"), Some(VariantKind::Unresumed));
        assert_eq!(VariantKind::from_struct_name("Returned"), Some(VariantKind::Returned));
        assert_eq!(VariantKind::from_struct_name("Panicked"), Some(VariantKind::Panicked));
        assert_eq!(VariantKind::from_struct_name("Suspend0"), Some(VariantKind::Suspend(0)));
        assert_eq!(VariantKind::from_struct_name("Suspend7"), Some(VariantKind::Suspend(7)));
        assert_eq!(VariantKind::from_struct_name("Nonsense"), None);
    }

    #[test]
    fn suspend_predicate() {
        assert!(VariantKind::Suspend(2).is_suspend());
        assert!(!VariantKind::Returned.is_suspend());
    }

    #[test]
    fn selects_variant_by_discriminant() {
        let mut variants = BTreeMap::new();
        variants.insert(0, VariantInfo::terminal(VariantKind::Unresumed));
        variants.insert(3, VariantInfo::terminal(VariantKind::Suspend(0)));
        let layout = AsyncFnLayout {
            type_name: "probe::sleeper::{async_fn_env#0}".to_string(),
            byte_size: 128,
            discr_offset: 120,
            discr_size: 1,
            variants,
        };
        assert_eq!(layout.variant_for(3).expect("suspend variant").kind, VariantKind::Suspend(0));
        assert!(layout.variant_for(9).is_none());
        assert_eq!(layout.short_name(), "sleeper");
    }

    #[test]
    fn registry_lookup_and_membership() {
        let mut layouts = AsyncLayouts::new();
        assert!(layouts.is_empty());
        layouts.insert(AsyncFnLayout {
            type_name: "a::b::{async_fn_env#0}".to_string(),
            byte_size: 8,
            discr_offset: 0,
            discr_size: 1,
            variants: BTreeMap::new(),
        });
        assert_eq!(layouts.len(), 1);
        assert!(layouts.is_coroutine("a::b::{async_fn_env#0}"));
        assert!(!layouts.is_coroutine("tokio::time::Sleep"));
        assert!(layouts.get("a::b::{async_fn_env#0}").is_some());
    }

    #[test]
    fn child_ref_constructor() {
        let c = ChildRef::new(8, "tokio::time::Sleep");
        assert_eq!(c.offset, 8);
        assert_eq!(c.type_name, "tokio::time::Sleep");
    }
}

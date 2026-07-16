//! DWARF-driven resolution of async fn coroutine layouts from a target binary.
//!
//! This is the only path (unlike the Go decoder, there is no vendored
//! fallback): rustc's `{async_fn_env#N}` layout is monomorphization- and
//! version-specific and exists solely in the binary's own DWARF. We reuse the
//! same `gimli`/`object` stack the `unwind` crate and Go decoder build on.
//!
//! What we read:
//! - **`DW_AT_producer`** on the first unit → the rustc version, gated by the
//!   layout DB ([`super::rustc_version`]).
//! - Every `{async_fn_env#N}` `DW_TAG_structure_type`, its
//!   `DW_TAG_variant_part` discriminant (`__state`), and each
//!   `DW_TAG_variant`'s state kind, `.await` source line, `__awaitee`
//!   (continuation), and inline child coroutines (`join!` fan-out).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use object::{Object, ObjectSymbol};

use crate::model::SourceLocation;

use super::error::AsyncDecodeError;
use super::layout::{AsyncFnLayout, AsyncLayouts, ChildRef, VariantInfo, VariantKind};
use super::rustc_version::{self, RustcVersion};

/// Max depth for the inline child-coroutine (`join!`/`select!`) descent,
/// bounding recursion through nested wrapper types (tuples, `MaybeDone`, …).
const MAX_CHILD_DEPTH: usize = 8;

type Reader<'a> = gimli::EndianSlice<'a, gimli::RunTimeEndian>;

/// Everything resolved from one async-Rust binary's DWARF.
#[derive(Debug, Clone)]
pub struct DwarfExtract {
    /// The rustc version the coroutine layout was validated against.
    pub version: RustcVersion,
    /// All recovered coroutine layouts.
    pub layouts: AsyncLayouts,
}

/// Whether `file` links the Tokio runtime: it exports a mangled
/// `tokio::runtime` symbol (`_ZN5tokio7runtime…`). A pure-`std`/futures async
/// program without Tokio is declined by [`super::TokioDecoder`] (its state-bit
/// reader is Tokio-specific), though the portable decode core would still
/// apply.
#[must_use]
pub fn is_tokio_object(file: &object::File) -> bool {
    file.symbols()
        .chain(file.dynamic_symbols())
        .any(|sym| sym.name().is_ok_and(|n| n.contains("5tokio7runtime")))
}

/// Parse `bytes` and extract every async fn coroutine layout.
///
/// # Errors
/// See [`AsyncDecodeError`]: not a Tokio binary, no DWARF, unsupported rustc,
/// or no coroutines found.
pub fn extract(bytes: &[u8]) -> Result<DwarfExtract, AsyncDecodeError> {
    let file = object::File::parse(bytes).map_err(|e| AsyncDecodeError::Object(e.to_string()))?;
    if !is_tokio_object(&file) {
        return Err(AsyncDecodeError::NotTokioBinary);
    }
    if object::Object::section_by_name(&file, ".debug_info").is_none() {
        return Err(AsyncDecodeError::NoDebugInfo);
    }

    let endian = if file.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    let load = |id: gimli::SectionId| -> Result<Cow<[u8]>, gimli::Error> {
        Ok(match object::Object::section_by_name(&file, id.name()) {
            Some(section) => object::ObjectSection::uncompressed_data(&section)
                .unwrap_or(Cow::Borrowed(&[][..])),
            None => Cow::Borrowed(&[][..]),
        })
    };
    let sections =
        gimli::DwarfSections::load(load).map_err(|e| AsyncDecodeError::Dwarf(e.to_string()))?;
    let dwarf = sections.borrow(|section| gimli::EndianSlice::new(section, endian));

    let mut version: Option<RustcVersion> = None;
    let mut layouts = AsyncLayouts::new();

    let mut units = dwarf.units();
    while let Some(header) = units.next().map_err(dwarf_err)? {
        let unit = dwarf.unit(header).map_err(dwarf_err)?;
        if version.is_none() {
            version = producer_version(&dwarf, &unit)?;
        }
        collect_unit(&dwarf, &unit, &mut layouts)?;
    }

    let version = version.ok_or_else(|| {
        AsyncDecodeError::UnsupportedLayout("no rustc producer string in DWARF".to_string())
    })?;
    if !rustc_version::is_supported(version) {
        return Err(AsyncDecodeError::UnsupportedLayout(format!(
            "rustc {}.{}.{} is outside the validated coroutine-layout window",
            version.major, version.minor, version.patch
        )));
    }
    if layouts.is_empty() {
        return Err(AsyncDecodeError::NoCoroutines);
    }
    Ok(DwarfExtract { version, layouts })
}

fn dwarf_err(e: gimli::Error) -> AsyncDecodeError {
    AsyncDecodeError::Dwarf(e.to_string())
}

/// The rustc version from a unit's `DW_AT_producer`, if it has one and parses.
fn producer_version(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
) -> Result<Option<RustcVersion>, AsyncDecodeError> {
    let mut entries = unit.entries();
    let Some((_, root)) = entries.next_dfs().map_err(dwarf_err)? else {
        return Ok(None);
    };
    let Some(value) = root.attr_value(gimli::DW_AT_producer).map_err(dwarf_err)? else {
        return Ok(None);
    };
    let reader = dwarf.attr_string(unit, value).map_err(dwarf_err)?;
    let producer = reader.to_string().map_err(dwarf_err)?.to_owned();
    Ok(RustcVersion::parse_producer(&producer))
}

/// A named type DIE's qualified name and offset, plus the coroutine set, built
/// in one namespace-aware DFS of a unit.
struct UnitIndex {
    names: HashMap<gimli::UnitOffset, String>,
    coroutines: HashSet<gimli::UnitOffset>,
}

/// Build the name index for a unit and turn each coroutine into a layout.
fn collect_unit(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    layouts: &mut AsyncLayouts,
) -> Result<(), AsyncDecodeError> {
    let index = build_index(dwarf, unit)?;
    for &offset in &index.coroutines {
        if let Some(layout) = build_layout(dwarf, unit, offset, &index)? {
            layouts.insert(layout);
        }
    }
    Ok(())
}

/// Namespace-aware DFS collecting qualified type names and coroutine offsets.
fn build_index(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
) -> Result<UnitIndex, AsyncDecodeError> {
    let mut names = HashMap::new();
    let mut coroutines = HashSet::new();
    let mut tree = unit.entries_tree(None).map_err(dwarf_err)?;
    let root = tree.root().map_err(dwarf_err)?;
    walk_names(dwarf, unit, root, &mut Vec::new(), &mut names, &mut coroutines)?;
    Ok(UnitIndex { names, coroutines })
}

fn walk_names(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    node: gimli::EntriesTreeNode<Reader>,
    path: &mut Vec<String>,
    names: &mut HashMap<gimli::UnitOffset, String>,
    coroutines: &mut HashSet<gimli::UnitOffset>,
) -> Result<(), AsyncDecodeError> {
    let (tag, offset, local) = {
        let entry = node.entry();
        (
            entry.tag(),
            entry.offset(),
            die_name(dwarf, unit, entry)?,
        )
    };

    let mut pushed = false;
    match tag {
        gimli::DW_TAG_namespace => {
            if let Some(name) = local {
                path.push(name);
                pushed = true;
            }
        }
        gimli::DW_TAG_structure_type | gimli::DW_TAG_enumeration_type => {
            if let Some(name) = &local {
                names.insert(offset, qualify(path, name));
                // A coroutine's DW_AT_name is exactly `{async_fn_env#N}` (or
                // the async-block form); match the prefix, not a substring, so
                // wrapper/tuple types whose *generic args* mention a coroutine
                // (e.g. `(MaybeDone<…{async_fn_env#0}>, …)`) are not mistaken
                // for coroutines themselves.
                if name.starts_with("{async_fn_env#") || name.starts_with("{async_block_env#") {
                    coroutines.insert(offset);
                }
                // Nested types (e.g. variant structs) are namespaced under
                // this type's name while we recurse into its children.
                path.push(name.clone());
                pushed = true;
            }
        }
        _ => {}
    }

    let mut children = node.children();
    while let Some(child) = children.next().map_err(dwarf_err)? {
        walk_names(dwarf, unit, child, path, names, coroutines)?;
    }
    if pushed {
        path.pop();
    }
    Ok(())
}

/// Build a layout for the coroutine DIE at `coro_off`, or `None` if it uses a
/// representation this decoder does not handle (e.g. a niche discriminant with
/// no `DW_AT_discr`) — declined honestly rather than guessed.
fn build_layout(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    coro_off: gimli::UnitOffset,
    index: &UnitIndex,
) -> Result<Option<AsyncFnLayout>, AsyncDecodeError> {
    let type_name = match index.names.get(&coro_off) {
        Some(name) => name.clone(),
        None => return Ok(None),
    };
    let mut tree = unit.entries_tree(Some(coro_off)).map_err(dwarf_err)?;
    let root = tree.root().map_err(dwarf_err)?;
    let byte_size = udata(root.entry(), gimli::DW_AT_byte_size).unwrap_or(0);

    // Locate the variant_part child.
    let mut children = root.children();
    while let Some(child) = children.next().map_err(dwarf_err)? {
        if child.entry().tag() == gimli::DW_TAG_variant_part {
            return build_from_variant_part(dwarf, unit, child, index, type_name, byte_size);
        }
    }
    Ok(None)
}

fn build_from_variant_part(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    vp: gimli::EntriesTreeNode<Reader>,
    index: &UnitIndex,
    type_name: String,
    byte_size: u64,
) -> Result<Option<AsyncFnLayout>, AsyncDecodeError> {
    let discr_ref = match vp.entry().attr_value(gimli::DW_AT_discr).map_err(dwarf_err)? {
        Some(gimli::AttributeValue::UnitRef(r)) => r,
        // No explicit discriminant (niche layout): decline this coroutine.
        _ => return Ok(None),
    };

    let mut discr_offset = None;
    let mut discr_size = 1u8;
    let mut variants = std::collections::BTreeMap::new();

    let mut children = vp.children();
    while let Some(child) = children.next().map_err(dwarf_err)? {
        let tag = child.entry().tag();
        if tag == gimli::DW_TAG_member && child.entry().offset() == discr_ref {
            discr_offset = udata(child.entry(), gimli::DW_AT_data_member_location);
            discr_size = discr_member_size(dwarf, unit, child.entry())?.unwrap_or(1);
        } else if tag == gimli::DW_TAG_variant {
            if let Some((value, info)) = read_variant(dwarf, unit, child, index)? {
                variants.insert(value, info);
            }
        }
    }

    let Some(discr_offset) = discr_offset else {
        return Ok(None);
    };
    Ok(Some(AsyncFnLayout {
        type_name,
        byte_size,
        discr_offset,
        discr_size,
        variants,
    }))
}

/// Read one `DW_TAG_variant`: its discriminant value and, via its single
/// member (the state struct), its kind, await line, awaitee and children.
fn read_variant(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    variant: gimli::EntriesTreeNode<Reader>,
    index: &UnitIndex,
) -> Result<Option<(u64, VariantInfo)>, AsyncDecodeError> {
    let discr_value = udata(variant.entry(), gimli::DW_AT_discr_value).unwrap_or(0);

    let mut children = variant.children();
    let Some(member) = children.next().map_err(dwarf_err)? else {
        return Ok(None);
    };
    let (state_ref, await_location) = {
        let entry = member.entry();
        let ty = match entry.attr_value(gimli::DW_AT_type).map_err(dwarf_err)? {
            Some(gimli::AttributeValue::UnitRef(r)) => r,
            _ => return Ok(None),
        };
        (ty, decl_location(dwarf, unit, entry)?)
    };

    let state = read_struct(dwarf, unit, state_ref)?;
    let Some(kind) = VariantKind::from_struct_name(&state.local_name) else {
        return Ok(None);
    };
    if !kind.is_suspend() {
        return Ok(Some((discr_value, VariantInfo::terminal(kind))));
    }

    let awaitee = state
        .members
        .iter()
        .find(|m| m.name == "__awaitee")
        .and_then(|m| child_ref(index, m));

    let mut children_out = Vec::new();
    let awaitee_offset = awaitee.as_ref().map(|a| a.offset);
    for member in &state.members {
        collect_children(
            dwarf,
            unit,
            member.type_ref,
            member.offset,
            index,
            awaitee_offset,
            0,
            &mut children_out,
        )?;
    }

    Ok(Some((
        discr_value,
        VariantInfo {
            kind,
            await_location,
            awaitee,
            children: children_out,
        },
    )))
}

/// A `ChildRef` for a member whose type is a coroutine or a leaf future.
fn child_ref(index: &UnitIndex, member: &MemberInfo) -> Option<ChildRef> {
    index
        .names
        .get(&member.type_ref)
        .map(|name| ChildRef::new(member.offset, name.clone()))
}

/// Recursively find inline child coroutines under `type_ref`, accumulating the
/// byte offset. Stops at (and records) a coroutine; stops at pointers; caps
/// depth. Excludes the member at `skip_offset` (the awaitee, already the
/// continuation, not a fan-out branch).
#[allow(clippy::too_many_arguments)]
fn collect_children(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    type_ref: gimli::UnitOffset,
    base: u64,
    index: &UnitIndex,
    skip_offset: Option<u64>,
    depth: usize,
    out: &mut Vec<ChildRef>,
) -> Result<(), AsyncDecodeError> {
    if depth > MAX_CHILD_DEPTH {
        return Ok(());
    }
    if index.coroutines.contains(&type_ref) {
        if Some(base) != skip_offset {
            if let Some(name) = index.names.get(&type_ref) {
                out.push(ChildRef::new(base, name.clone()));
            }
        }
        return Ok(());
    }
    let info = read_struct(dwarf, unit, type_ref)?;
    for member in info.members {
        collect_children(
            dwarf,
            unit,
            member.type_ref,
            base + member.offset,
            index,
            skip_offset,
            depth + 1,
            out,
        )?;
    }
    Ok(())
}

/// One member of a struct/variant: name, byte offset, and referenced type.
struct MemberInfo {
    name: String,
    offset: u64,
    type_ref: gimli::UnitOffset,
}

/// A lightweight read of a struct-like DIE (structure_type, or a variant's
/// payload): its local name and direct members. For an enum-like type it
/// descends the `DW_TAG_variant_part` and flattens each variant's payload
/// members (with their offsets) so a `join!`'s `MaybeDone` wrappers are seen.
struct StructInfo {
    local_name: String,
    members: Vec<MemberInfo>,
}

fn read_struct(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    offset: gimli::UnitOffset,
) -> Result<StructInfo, AsyncDecodeError> {
    let mut tree = unit.entries_tree(Some(offset)).map_err(dwarf_err)?;
    let root = tree.root().map_err(dwarf_err)?;
    let local_name = die_name(dwarf, unit, root.entry())?.unwrap_or_default();
    let mut members = Vec::new();
    read_members(dwarf, unit, root, 0, &mut members)?;
    Ok(StructInfo {
        local_name,
        members,
    })
}

/// Collect direct `DW_TAG_member`s and, for a nested `DW_TAG_variant_part`,
/// each variant payload's members (offset added), so enum wrappers are
/// transparent to the child search.
fn read_members(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    node: gimli::EntriesTreeNode<Reader>,
    base: u64,
    out: &mut Vec<MemberInfo>,
) -> Result<(), AsyncDecodeError> {
    let mut children = node.children();
    while let Some(child) = children.next().map_err(dwarf_err)? {
        let tag = child.entry().tag();
        if tag == gimli::DW_TAG_member {
            let entry = child.entry();
            let name = die_name(dwarf, unit, entry)?.unwrap_or_default();
            let offset = base + udata(entry, gimli::DW_AT_data_member_location).unwrap_or(0);
            if let Some(gimli::AttributeValue::UnitRef(type_ref)) =
                entry.attr_value(gimli::DW_AT_type).map_err(dwarf_err)?
            {
                out.push(MemberInfo {
                    name,
                    offset,
                    type_ref,
                });
            }
        } else if tag == gimli::DW_TAG_variant_part {
            read_variant_payloads(dwarf, unit, child, base, out)?;
        }
    }
    Ok(())
}

/// For an enum (`DW_TAG_variant_part`), flatten every variant's payload member
/// so the inline-coroutine search sees through `MaybeDone`/`Option` wrappers.
fn read_variant_payloads(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    node: gimli::EntriesTreeNode<Reader>,
    base: u64,
    out: &mut Vec<MemberInfo>,
) -> Result<(), AsyncDecodeError> {
    let mut variants = node.children();
    while let Some(variant) = variants.next().map_err(dwarf_err)? {
        if variant.entry().tag() != gimli::DW_TAG_variant {
            continue;
        }
        let mut members = variant.children();
        while let Some(member) = members.next().map_err(dwarf_err)? {
            if member.entry().tag() != gimli::DW_TAG_member {
                continue;
            }
            let entry = member.entry();
            let name = die_name(dwarf, unit, entry)?.unwrap_or_default();
            let offset = base + udata(entry, gimli::DW_AT_data_member_location).unwrap_or(0);
            if let Some(gimli::AttributeValue::UnitRef(type_ref)) =
                entry.attr_value(gimli::DW_AT_type).map_err(dwarf_err)?
            {
                out.push(MemberInfo {
                    name,
                    offset,
                    type_ref,
                });
            }
        }
    }
    Ok(())
}

/// The byte size of the discriminant member's referenced type.
fn discr_member_size(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    entry: &gimli::DebuggingInformationEntry<Reader>,
) -> Result<Option<u8>, AsyncDecodeError> {
    let Some(gimli::AttributeValue::UnitRef(type_ref)) =
        entry.attr_value(gimli::DW_AT_type).map_err(dwarf_err)?
    else {
        return Ok(None);
    };
    let mut tree = unit.entries_tree(Some(type_ref)).map_err(dwarf_err)?;
    let root = tree.root().map_err(dwarf_err)?;
    let _ = dwarf;
    Ok(udata(root.entry(), gimli::DW_AT_byte_size).map(|s| s as u8))
}

/// Resolve a member's `DW_AT_decl_file`/`DW_AT_decl_line` into a source
/// location via the unit's line program file table.
fn decl_location(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    entry: &gimli::DebuggingInformationEntry<Reader>,
) -> Result<Option<SourceLocation>, AsyncDecodeError> {
    let Some(line) = udata(entry, gimli::DW_AT_decl_line) else {
        return Ok(None);
    };
    let file_index = udata(entry, gimli::DW_AT_decl_file);
    let path = file_index
        .and_then(|idx| file_name(dwarf, unit, idx))
        .unwrap_or_default();
    Ok(Some(SourceLocation {
        path,
        line: line as u32,
        column: 0,
    }))
}

/// The file name for a `DW_AT_decl_file` index, from the unit's line program.
fn file_name(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    index: u64,
) -> Option<String> {
    let program = unit.line_program.as_ref()?;
    let header = program.header();
    let file = header.file(index)?;
    let value = file.path_name();
    let reader = dwarf.attr_string(unit, value).ok()?;
    reader.to_string().ok().map(|s| s.to_owned())
}

/// The `DW_AT_name` of a DIE as an owned string.
fn die_name(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    entry: &gimli::DebuggingInformationEntry<Reader>,
) -> Result<Option<String>, AsyncDecodeError> {
    match entry.attr_value(gimli::DW_AT_name).map_err(dwarf_err)? {
        Some(value) => {
            let s = dwarf.attr_string(unit, value).map_err(dwarf_err)?;
            Ok(Some(s.to_string().map_err(dwarf_err)?.to_owned()))
        }
        None => Ok(None),
    }
}

/// A DIE attribute read as an unsigned constant.
fn udata(entry: &gimli::DebuggingInformationEntry<Reader>, attr: gimli::DwAt) -> Option<u64> {
    entry.attr(attr).ok().flatten().and_then(|a| a.udata_value())
}

/// Join a namespace path and a local name into a qualified type name.
fn qualify(path: &[String], name: &str) -> String {
    if path.is_empty() {
        name.to_string()
    } else {
        format!("{}::{name}", path.join("::"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualify_joins_namespace_path() {
        assert_eq!(
            qualify(&["probe".to_string(), "sleeper".to_string()], "{async_fn_env#0}"),
            "probe::sleeper::{async_fn_env#0}"
        );
        assert_eq!(qualify(&[], "Sleep"), "Sleep");
    }

    #[test]
    fn non_object_bytes_are_not_tokio() {
        assert!(object::File::parse(&b"not elf"[..]).is_err());
    }
}

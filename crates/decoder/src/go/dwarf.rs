//! DWARF-driven resolution of the Go runtime layout from a target binary.
//!
//! This is the preferred path (`CLAUDE.md`: "vendor Delve's runtime offset
//! tables" — but DWARF-derived offsets self-adapt per Go version, so we read
//! them straight from the binary and keep the vendored table only as a
//! stripped-DWARF fallback). We reuse the same `gimli`/`object` stack the
//! `unwind` crate already builds on (see `crates/unwind/src/elf.rs`).
//!
//! What we read from the binary:
//! - **Symbol addresses** for `runtime.allgs` (the `[]*g` slice header) and
//!   `runtime.allglen`, from the ELF symbol table, falling back to the DWARF
//!   variable's `DW_OP_addr` location when the symbol table is stripped.
//! - **Struct member offsets** for `runtime.g`, `runtime.gobuf`,
//!   `runtime.stack`, and `runtime.m`, from `.debug_info`.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use gimli::Reader as _;
use object::{Object, ObjectSection, ObjectSymbol};

use super::error::GoDecodeError;
use super::offsets::GStructOffsets;

/// Everything resolvable from one Go binary's ELF + DWARF.
#[derive(Debug, Clone)]
pub struct DwarfExtract {
    /// Target pointer width in bytes.
    pub ptr_size: u8,
    /// Address of the `runtime.allgs` slice header, if found.
    pub allgs_addr: Option<u64>,
    /// Address of `runtime.allglen`, if found.
    pub allglen_addr: Option<u64>,
    /// `g` field offsets resolved from DWARF, plus the `m.procid` offset.
    /// `None` when DWARF is absent or incomplete.
    pub offsets: Option<(GStructOffsets, Option<u64>)>,
}

/// Whether `file` looks like a Go binary: it has the `.go.buildinfo` section
/// the Go linker always emits, or exports the `runtime.allgs` symbol.
#[must_use]
pub fn is_go_object(file: &object::File) -> bool {
    if file.section_by_name(".go.buildinfo").is_some() {
        return true;
    }
    file.symbols()
        .any(|sym| sym.name() == Ok("runtime.allgs"))
}

/// Parse `bytes` as an object file and extract the Go runtime layout.
///
/// # Errors
/// Returns [`GoDecodeError::Object`] if the bytes are not a parseable object
/// file, or [`GoDecodeError::Dwarf`] if DWARF parsing fails.
pub fn extract(bytes: &[u8]) -> Result<DwarfExtract, GoDecodeError> {
    let file = object::File::parse(bytes).map_err(|e| GoDecodeError::Object(e.to_string()))?;
    let ptr_size = if file.is_64() { 8 } else { 4 };

    let mut allgs_addr = symbol_addr(&file, "runtime.allgs");
    let mut allglen_addr = symbol_addr(&file, "runtime.allglen");

    let (structs, variables) = read_dwarf(&file)?;
    allgs_addr = allgs_addr.or_else(|| variables.get("runtime.allgs").copied());
    allglen_addr = allglen_addr.or_else(|| variables.get("runtime.allglen").copied());

    Ok(DwarfExtract {
        ptr_size,
        allgs_addr,
        allglen_addr,
        offsets: assemble_offsets(&structs),
    })
}

/// Address of a named symbol from the ELF symbol table, if present.
fn symbol_addr(file: &object::File, name: &str) -> Option<u64> {
    file.symbols()
        .find(|sym| sym.name() == Ok(name))
        .map(|sym| sym.address())
}

/// Compose the flat [`GStructOffsets`] from the per-struct member maps.
/// Returns `None` if any required struct/field is missing (incomplete DWARF).
fn assemble_offsets(
    structs: &HashMap<String, HashMap<String, u64>>,
) -> Option<(GStructOffsets, Option<u64>)> {
    let g = structs.get("runtime.g")?;
    let gobuf = structs.get("runtime.gobuf")?;
    let stack = structs.get("runtime.stack")?;

    let stack_off = *g.get("stack")?;
    let sched_off = *g.get("sched")?;

    let offsets = GStructOffsets {
        goid: *g.get("goid")?,
        atomicstatus: *g.get("atomicstatus")?,
        waitreason: *g.get("waitreason")?,
        stack_lo: stack_off + *stack.get("lo")?,
        stack_hi: stack_off + *stack.get("hi")?,
        sched_pc: sched_off + *gobuf.get("pc")?,
        sched_sp: sched_off + *gobuf.get("sp")?,
        gopc: *g.get("gopc")?,
        startpc: *g.get("startpc")?,
        m: *g.get("m")?,
        parent_goid: g.get("parentGoid").copied(),
    };
    let m_procid = structs
        .get("runtime.m")
        .and_then(|m| m.get("procid").copied());
    Some((offsets, m_procid))
}

type StructMap = HashMap<String, HashMap<String, u64>>;
type VarMap = HashMap<String, u64>;

/// The struct types whose member offsets the decoder needs.
const TARGET_STRUCTS: &[&str] = &["runtime.g", "runtime.gobuf", "runtime.stack", "runtime.m"];

/// The runtime globals whose addresses we recover from DWARF variables.
const TARGET_VARS: &[&str] = &["runtime.allgs", "runtime.allglen"];

/// Read struct member offsets and variable addresses out of the file's DWARF.
fn read_dwarf(file: &object::File) -> Result<(StructMap, VarMap), GoDecodeError> {
    let endian = if file.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    let load = |id: gimli::SectionId| -> Result<Cow<[u8]>, gimli::Error> {
        Ok(match file.section_by_name(id.name()) {
            Some(section) => section
                .uncompressed_data()
                .unwrap_or(Cow::Borrowed(&[][..])),
            None => Cow::Borrowed(&[][..]),
        })
    };
    let sections =
        gimli::DwarfSections::load(load).map_err(|e| GoDecodeError::Dwarf(e.to_string()))?;
    let dwarf = sections.borrow(|section| gimli::EndianSlice::new(section, endian));

    let targets: HashSet<&str> = TARGET_STRUCTS.iter().copied().collect();
    let vars_wanted: HashSet<&str> = TARGET_VARS.iter().copied().collect();
    let mut structs = StructMap::new();
    let mut vars = VarMap::new();

    let mut units = dwarf.units();
    while let Some(header) = units.next().map_err(dwarf_err)? {
        let unit = dwarf.unit(header).map_err(dwarf_err)?;
        let mut tree = unit.entries_tree(None).map_err(dwarf_err)?;
        let root = tree.root().map_err(dwarf_err)?;
        walk(&dwarf, &unit, root, &targets, &vars_wanted, &mut structs, &mut vars)
            .map_err(dwarf_err)?;
    }
    Ok((structs, vars))
}

fn dwarf_err(e: gimli::Error) -> GoDecodeError {
    GoDecodeError::Dwarf(e.to_string())
}

type Reader<'a> = gimli::EndianSlice<'a, gimli::RunTimeEndian>;

/// Depth-first walk collecting target struct members and variable addresses.
fn walk(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    node: gimli::EntriesTreeNode<Reader>,
    targets: &HashSet<&str>,
    vars_wanted: &HashSet<&str>,
    structs: &mut StructMap,
    vars: &mut VarMap,
) -> Result<(), gimli::Error> {
    let (tag, name, var_addr) = {
        let entry = node.entry();
        let tag = entry.tag();
        let name = die_name(dwarf, unit, entry)?;
        let addr = if tag == gimli::DW_TAG_variable {
            variable_addr(entry, unit.encoding().address_size)?
        } else {
            None
        };
        (tag, name, addr)
    };

    if tag == gimli::DW_TAG_structure_type {
        if let Some(name) = name.filter(|n| targets.contains(n.as_str())) {
            let members = read_members(dwarf, unit, node)?;
            structs.entry(name).or_insert(members);
            return Ok(());
        }
    } else if tag == gimli::DW_TAG_variable {
        if let (Some(name), Some(addr)) = (&name, var_addr) {
            if vars_wanted.contains(name.as_str()) {
                vars.entry(name.clone()).or_insert(addr);
            }
        }
    }

    let mut children = node.children();
    while let Some(child) = children.next()? {
        walk(dwarf, unit, child, targets, vars_wanted, structs, vars)?;
    }
    Ok(())
}

/// Collect `name -> data_member_location` for a struct DIE's members.
fn read_members(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    node: gimli::EntriesTreeNode<Reader>,
) -> Result<HashMap<String, u64>, gimli::Error> {
    let mut members = HashMap::new();
    let mut children = node.children();
    while let Some(child) = children.next()? {
        let entry = child.entry();
        if entry.tag() != gimli::DW_TAG_member {
            continue;
        }
        if let (Some(name), Some(offset)) = (die_name(dwarf, unit, entry)?, member_offset(entry)?) {
            members.insert(name, offset);
        }
    }
    Ok(members)
}

/// The `DW_AT_name` of a DIE, resolved to an owned string.
fn die_name(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    entry: &gimli::DebuggingInformationEntry<Reader>,
) -> Result<Option<String>, gimli::Error> {
    match entry.attr_value(gimli::DW_AT_name)? {
        Some(value) => {
            let s = dwarf.attr_string(unit, value)?;
            Ok(Some(s.to_string()?.to_owned()))
        }
        None => Ok(None),
    }
}

/// The `DW_AT_data_member_location` of a member DIE as a constant offset.
fn member_offset(
    entry: &gimli::DebuggingInformationEntry<Reader>,
) -> Result<Option<u64>, gimli::Error> {
    Ok(entry
        .attr(gimli::DW_AT_data_member_location)?
        .and_then(|attr| attr.udata_value()))
}

/// A variable DIE's static address from a `DW_OP_addr` location expression.
///
/// Non-fatal by design: most `DW_TAG_variable` DIEs are locals whose location
/// is a short, non-`DW_OP_addr` expression (`DW_OP_fbreg`, a loclist, …) that
/// would run the reader out of bytes. Any such read failure is mapped to
/// `None` (this variable simply has no static address) rather than aborting
/// the whole DWARF walk.
fn variable_addr(
    entry: &gimli::DebuggingInformationEntry<Reader>,
    address_size: u8,
) -> Result<Option<u64>, gimli::Error> {
    let Some(gimli::AttributeValue::Exprloc(expr)) = entry.attr_value(gimli::DW_AT_location)? else {
        return Ok(None);
    };
    let mut reader = expr.0;
    // DW_OP_addr (0x03) followed by a target-sized absolute address; a shorter
    // or differently-opcoded expression is not a static address.
    Ok(match reader.read_u8() {
        Ok(0x03) => reader.read_address(address_size).ok(),
        _ => None,
    })
}

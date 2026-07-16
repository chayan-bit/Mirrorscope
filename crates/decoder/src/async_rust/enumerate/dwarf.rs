//! Per-binary facts that live enumeration needs but that are *not* stable
//! across builds (so cannot be vendored): the `CONTEXT` thread-local's TLS
//! offset, the executable's TLS/load geometry, and the map from each
//! monomorphized `raw::poll::<T, S>` function address to its future type `T`.
//!
//! These come from the target's own symbol table, program headers, and DWARF —
//! the same `object`/`gimli` stack the Go and coroutine decoders use.

use std::borrow::Cow;

use object::{Object, ObjectSymbol, SymbolKind};

use super::error::EnumerateError;
use super::layout::TokioVersion;

/// Everything mined from one Tokio binary that enumeration composes with the
/// vendored [`super::layout::TokioRuntimeLayout`].
#[derive(Debug, Clone)]
pub struct BinaryFacts {
    /// The embedded Tokio version, keying the vendored internal layout.
    pub version: TokioVersion,
    /// `CONTEXT`'s `st_value`: its offset within the executable's TLS block.
    pub context_tls_offset: u64,
    /// Alignment of the executable's `PT_TLS` segment.
    pub tls_align: u64,
    /// Size of the executable's static TLS block (`PT_TLS` `p_memsz`).
    pub tls_block_size: u64,
    /// Minimum `PT_LOAD` virtual address, subtracted from the runtime load
    /// base to recover the load bias.
    pub min_load_vaddr: u64,
    /// `(static low_pc, future type name)` for every `raw::poll::<T, S>`.
    poll_types: Vec<(u64, String)>,
}

impl BinaryFacts {
    /// The future type `T` of a task whose (de-biased, static) poll-function
    /// address is `static_addr`, if that address is a known `poll<T, S>`.
    #[must_use]
    pub fn future_type_for(&self, static_addr: u64) -> Option<&str> {
        self.poll_types
            .iter()
            .find(|(addr, _)| *addr == static_addr)
            .map(|(_, name)| name.as_str())
    }

    /// Number of resolved poll-function type mappings (diagnostics/tests).
    #[must_use]
    pub fn poll_type_count(&self) -> usize {
        self.poll_types.len()
    }
}

/// Mine the per-binary enumeration facts from `image`.
///
/// # Errors
/// Declines with an [`EnumerateError`] if the version, TLS symbol, or DWARF is
/// missing — enumeration then falls back honestly.
pub fn resolve(image: &[u8]) -> Result<BinaryFacts, EnumerateError> {
    let version =
        TokioVersion::detect_in_bytes(image).ok_or(EnumerateError::TokioVersionUnknown)?;
    let file = object::File::parse(image).map_err(|e| EnumerateError::Parse(e.to_string()))?;
    let context_tls_offset = context_tls_offset(&file)?;
    if object::Object::section_by_name(&file, ".debug_info").is_none() {
        return Err(EnumerateError::NoDebugInfo);
    }
    let (tls_align, tls_block_size, min_load_vaddr) = elf_geometry(image)?;
    let poll_types = poll_type_map(&file)?;
    Ok(BinaryFacts {
        version,
        context_tls_offset,
        tls_align,
        tls_block_size,
        min_load_vaddr,
        poll_types,
    })
}

/// The `st_value` of the `tokio::runtime::context::CONTEXT` TLS symbol.
fn context_tls_offset(file: &object::File) -> Result<u64, EnumerateError> {
    file.symbols()
        .find(|s| s.kind() == SymbolKind::Tls && s.name().is_ok_and(is_context_symbol))
        .map(|s| s.address())
        .ok_or(EnumerateError::ContextSymbolMissing)
}

/// Whether a (mangled) symbol name is the `context::CONTEXT` thread-local.
fn is_context_symbol(name: &str) -> bool {
    name.contains("7context7CONTEXT") || name.contains("context..CONTEXT")
}

/// Parse the ELF program headers for `(tls_align, tls_memsz, min_load_vaddr)`.
///
/// Reads the raw ELF64 little-endian program-header table directly: `object`
/// exposes load segments but not `PT_TLS` geometry, which the TLS math needs.
fn elf_geometry(image: &[u8]) -> Result<(u64, u64, u64), EnumerateError> {
    const PT_LOAD: u32 = 1;
    const PT_TLS: u32 = 7;
    if image.len() < 64 || &image[..4] != b"\x7fELF" || image[4] != 2 || image[5] != 1 {
        return Err(EnumerateError::Parse(
            "not a little-endian ELF64 image".to_string(),
        ));
    }
    let phoff = u64::from_le_bytes(word(image, 32)?) as usize;
    let phentsize = u16::from_le_bytes(half(image, 54)?) as usize;
    let phnum = u16::from_le_bytes(half(image, 56)?) as usize;

    let mut tls_align = 8u64;
    let mut tls_memsz = 0u64;
    let mut min_load = u64::MAX;
    for i in 0..phnum {
        let base = phoff + i * phentsize;
        let p_type = u32::from_le_bytes(quarter(image, base)?);
        let p_vaddr = u64::from_le_bytes(word(image, base + 16)?);
        let p_memsz = u64::from_le_bytes(word(image, base + 40)?);
        let p_align = u64::from_le_bytes(word(image, base + 48)?);
        match p_type {
            PT_TLS => {
                tls_align = p_align.max(1);
                tls_memsz = p_memsz;
            }
            PT_LOAD => min_load = min_load.min(p_vaddr),
            _ => {}
        }
    }
    Ok((
        tls_align,
        tls_memsz,
        if min_load == u64::MAX { 0 } else { min_load },
    ))
}

fn word(b: &[u8], at: usize) -> Result<[u8; 8], EnumerateError> {
    b.get(at..at + 8)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| EnumerateError::Parse("truncated ELF header".to_string()))
}
fn quarter(b: &[u8], at: usize) -> Result<[u8; 4], EnumerateError> {
    b.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| EnumerateError::Parse("truncated ELF header".to_string()))
}
fn half(b: &[u8], at: usize) -> Result<[u8; 2], EnumerateError> {
    b.get(at..at + 2)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| EnumerateError::Parse("truncated ELF header".to_string()))
}

type Reader<'a> = gimli::EndianSlice<'a, gimli::RunTimeEndian>;

/// Build the `static low_pc → future type` map from every `raw::poll::<T, S>`
/// subprogram DIE in the binary's DWARF.
fn poll_type_map(file: &object::File) -> Result<Vec<(u64, String)>, EnumerateError> {
    let endian = if file.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    let load = |id: gimli::SectionId| -> Result<Cow<[u8]>, gimli::Error> {
        Ok(match object::Object::section_by_name(file, id.name()) {
            Some(s) => {
                object::ObjectSection::uncompressed_data(&s).unwrap_or(Cow::Borrowed(&[][..]))
            }
            None => Cow::Borrowed(&[][..]),
        })
    };
    let sections = gimli::DwarfSections::load(load).map_err(dwarf_err)?;
    let dwarf = sections.borrow(|s| gimli::EndianSlice::new(s, endian));

    let mut out = Vec::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next().map_err(dwarf_err)? {
        let unit = dwarf.unit(header).map_err(dwarf_err)?;
        collect_polls(&dwarf, &unit, &mut out)?;
    }
    Ok(out)
}

/// Scan a unit for `poll<…>` subprograms with a low_pc, recording `(addr, T)`.
fn collect_polls(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    out: &mut Vec<(u64, String)>,
) -> Result<(), EnumerateError> {
    let mut entries = unit.entries();
    while let Some((_, entry)) = entries.next_dfs().map_err(dwarf_err)? {
        if entry.tag() != gimli::DW_TAG_subprogram {
            continue;
        }
        let Some(name) = die_name(dwarf, unit, entry)? else {
            continue;
        };
        if !name.starts_with("poll<") {
            continue;
        }
        let Some(future) = first_generic_arg(&name) else {
            continue;
        };
        if let Some(addr) = low_pc(dwarf, unit, entry)? {
            out.push((addr, future));
        }
    }
    Ok(())
}

/// Extract the first generic argument `T` from a `poll<T, S>` name, splitting
/// at the top-level comma so nested generics in `T` are preserved.
fn first_generic_arg(name: &str) -> Option<String> {
    let inner = name.strip_prefix("poll<")?;
    let mut depth = 0usize;
    for (i, c) in inner.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                if depth == 0 {
                    return Some(inner[..i].trim().to_string());
                }
                depth -= 1;
            }
            ',' if depth == 0 => return Some(inner[..i].trim().to_string()),
            _ => {}
        }
    }
    None
}

fn low_pc(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    entry: &gimli::DebuggingInformationEntry<Reader>,
) -> Result<Option<u64>, EnumerateError> {
    match entry.attr_value(gimli::DW_AT_low_pc).map_err(dwarf_err)? {
        Some(value) => Ok(dwarf.attr_address(unit, value).map_err(dwarf_err)?),
        None => Ok(None),
    }
}

fn die_name(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    entry: &gimli::DebuggingInformationEntry<Reader>,
) -> Result<Option<String>, EnumerateError> {
    match entry.attr_value(gimli::DW_AT_name).map_err(dwarf_err)? {
        Some(value) => {
            let s = dwarf.attr_string(unit, value).map_err(dwarf_err)?;
            Ok(Some(s.to_string().map_err(dwarf_err)?.to_owned()))
        }
        None => Ok(None),
    }
}

fn dwarf_err(e: gimli::Error) -> EnumerateError {
    EnumerateError::Parse(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_first_generic_arg() {
        assert_eq!(
            first_generic_arg("poll<tokfix::sleeper::{async_fn_env#0}, alloc::sync::Arc<H>>")
                .as_deref(),
            Some("tokfix::sleeper::{async_fn_env#0}")
        );
    }

    #[test]
    fn preserves_nested_generics_in_first_arg() {
        assert_eq!(
            first_generic_arg("poll<core::pin::Pin<Box<F, G>>, S>").as_deref(),
            Some("core::pin::Pin<Box<F, G>>")
        );
    }

    #[test]
    fn ignores_non_poll_names() {
        assert_eq!(first_generic_arg("poll_future<F, S>"), None);
    }

    #[test]
    fn recognizes_context_symbol_forms() {
        assert!(is_context_symbol("_ZN5tokio7runtime7context7CONTEXT29foo"));
        assert!(is_context_symbol("tokio..runtime..context..CONTEXT..bar"));
        assert!(!is_context_symbol("_ZN5tokio7runtime7context11set_current"));
    }

    #[test]
    fn rejects_non_elf_geometry() {
        assert!(matches!(
            elf_geometry(b"not an elf"),
            Err(EnumerateError::Parse(_))
        ));
    }
}

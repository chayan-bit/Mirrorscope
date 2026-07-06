//! ELF parsing helpers shared by the unwinder and the symbolizer.
//!
//! Both need the same load-bias arithmetic; keeping it here means the AVMA
//! <-> SVMA relationship is computed once, consistently. See the crate docs
//! for the address vocabulary.

use std::ops::Range;
use std::path::Path;

use object::{Object, ObjectSection, ObjectSegment};

use crate::UnwindError;

/// A section's stated address range plus its bytes.
pub(crate) struct SectionData {
    /// The section's SVMA range (as written in the ELF).
    pub svma: Range<u64>,
    /// The section's raw bytes.
    pub bytes: Vec<u8>,
}

/// Everything the unwinder needs from one ELF module.
pub(crate) struct ElfLayout {
    /// Value such that `avma = base_avma + svma` (ELF `base_svma` is `0`).
    pub base_avma: u64,
    /// The module's mapped AVMA range, used to locate it by program counter.
    pub avma_range: Range<u64>,
    /// The `.text` section, for prologue/epilogue instruction analysis.
    pub text: Option<SectionData>,
    /// The `.eh_frame` section (DWARF CFI).
    pub eh_frame: Option<SectionData>,
    /// The `.eh_frame_hdr` section (binary-search index over `.eh_frame`).
    pub eh_frame_hdr: Option<SectionData>,
    /// The `.got` SVMA range, used to resolve GOT-relative CFI addresses.
    pub got_svma: Option<Range<u64>>,
}

/// Read the full section layout of a module mapped at `mapping_base`.
pub(crate) fn read_layout(path: &Path, mapping_base: u64) -> Result<ElfLayout, UnwindError> {
    let data = std::fs::read(path).map_err(|source| UnwindError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let file = object::File::parse(&*data)
        .map_err(|e| UnwindError::Elf(format!("{}: {e}", path.display())))?;

    let (base_avma, avma_range) = bounds(&file, mapping_base)?;
    Ok(ElfLayout {
        base_avma,
        avma_range,
        text: section(&file, ".text"),
        eh_frame: section(&file, ".eh_frame"),
        eh_frame_hdr: section(&file, ".eh_frame_hdr"),
        got_svma: file
            .section_by_name(".got")
            .map(|s| s.address()..s.address() + s.size()),
    })
}

/// Read only the load bias and mapped range of a module (no section bytes).
///
/// This is the cheap path the symbolizer uses; `addr2line` reads the DWARF
/// itself, so only the AVMA -> SVMA conversion is needed here.
pub(crate) fn module_bounds(
    path: &Path,
    mapping_base: u64,
) -> Result<(u64, Range<u64>), UnwindError> {
    let data = std::fs::read(path).map_err(|source| UnwindError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let file = object::File::parse(&*data)
        .map_err(|e| UnwindError::Elf(format!("{}: {e}", path.display())))?;
    bounds(&file, mapping_base)
}

/// Derive `base_avma` and the mapped AVMA range from the ELF program headers.
///
/// The ELF load bias is a single value `B` with `avma = svma + B` for the whole
/// image. Anchoring on the lowest loadable segment gives `B = mapping_base -
/// min_vaddr`: for PIE (`min_vaddr == 0`) that is the mapping base itself; for
/// non-PIE (`min_vaddr == 0x400000`, mapped at `0x400000`) it is `0`.
fn bounds<'d>(file: &impl Object<'d>, mapping_base: u64) -> Result<(u64, Range<u64>), UnwindError> {
    let mut min_vaddr = u64::MAX;
    let mut max_vaddr_end = 0u64;
    for segment in file.segments() {
        let start = segment.address();
        min_vaddr = min_vaddr.min(start);
        max_vaddr_end = max_vaddr_end.max(start + segment.size());
    }
    if min_vaddr == u64::MAX {
        return Err(UnwindError::Elf("no loadable segments".to_string()));
    }
    let base_avma = mapping_base.wrapping_sub(min_vaddr);
    let avma_range = (base_avma + min_vaddr)..(base_avma + max_vaddr_end);
    Ok((base_avma, avma_range))
}

/// Extract one section's SVMA range and bytes, if present and readable.
fn section<'d>(file: &impl Object<'d>, name: &str) -> Option<SectionData> {
    let section = file.section_by_name(name)?;
    let address = section.address();
    let size = section.size();
    let bytes = section.data().ok()?.to_vec();
    Some(SectionData {
        svma: address..address + size,
        bytes,
    })
}

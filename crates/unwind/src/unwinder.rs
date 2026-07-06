//! Native stack unwinding via [`framehop`].
//!
//! The concrete architecture (x86-64 or aarch64) is selected at compile time
//! with `cfg(target_arch)`, mirroring how the recorder selects its register
//! layout. The public surface is architecture-neutral: callers hand in
//! [`InitialRegs`] and get back a list of frame lookup addresses.

use std::ops::Range;
use std::path::Path;

use framehop::{
    CacheNative, ExplicitModuleSectionInfo, MayAllocateDuringUnwind, Module, UnwindRegsNative,
    Unwinder, UnwinderNative,
};

use crate::elf::{self, SectionData};
use crate::{InitialRegs, MemoryReader, UnwindError};

/// Section data type handed to framehop. Owning `Vec<u8>` keeps modules
/// self-contained for the lifetime of the unwinder.
type Sections = Vec<u8>;

/// Unwinds native stacks for a set of loaded modules.
///
/// Add every module in the target with [`add_module`](Self::add_module), then
/// call [`unwind`](Self::unwind) with the leaf registers and a
/// [`MemoryReader`] over the target's stack.
pub struct StackUnwinder {
    unwinder: UnwinderNative<Sections, MayAllocateDuringUnwind>,
    cache: CacheNative<MayAllocateDuringUnwind>,
}

impl StackUnwinder {
    /// Create an empty unwinder with no modules loaded.
    pub fn new() -> Self {
        Self {
            unwinder: UnwinderNative::new(),
            cache: CacheNative::new(),
        }
    }

    /// Register a module loaded at `mapping_base` (its load address from
    /// `/proc/<pid>/maps`).
    ///
    /// Parses the ELF at `path`, feeding framehop the `.text`, `.eh_frame`,
    /// `.eh_frame_hdr`, and `.got` sections it needs for CFI unwinding.
    pub fn add_module(&mut self, path: &Path, mapping_base: u64) -> Result<(), UnwindError> {
        let layout = elf::read_layout(path, mapping_base)?;
        let (text_svma, text) = split(layout.text);
        let (eh_frame_svma, eh_frame) = split(layout.eh_frame);
        let (eh_frame_hdr_svma, eh_frame_hdr) = split(layout.eh_frame_hdr);

        let section_info = ExplicitModuleSectionInfo {
            base_svma: 0,
            text_svma,
            text,
            eh_frame_svma,
            eh_frame,
            eh_frame_hdr_svma,
            eh_frame_hdr,
            got_svma: layout.got_svma,
            ..Default::default()
        };
        let module = Module::new(
            path.display().to_string(),
            layout.avma_range,
            layout.base_avma,
            section_info,
        );
        self.unwinder.add_module(module);
        Ok(())
    }

    /// Unwind from `regs`, reading stack memory through `mem`.
    ///
    /// Returns frame *lookup* addresses (return addresses are biased back by
    /// one byte so they symbolize to the calling line), innermost frame first.
    /// Following framehop's guidance, a terminal error from the iterator ends
    /// the walk without discarding frames already recovered.
    pub fn unwind(
        &mut self,
        regs: &InitialRegs,
        mem: &mut impl MemoryReader,
    ) -> Result<Vec<u64>, UnwindError> {
        let mut read_stack = |addr: u64| mem.read_u64(addr).map_err(|_| ());
        let mut frames = Vec::new();
        let mut iter =
            self.unwinder
                .iter_frames(regs.pc, native_regs(regs), &mut self.cache, &mut read_stack);
        // A terminal `Err` from framehop ends the walk (it may signal either a
        // truncated stack or the root); collected frames are kept regardless.
        while let Ok(Some(frame)) = iter.next() {
            frames.push(frame.address_for_lookup());
        }
        Ok(frames)
    }
}

impl Default for StackUnwinder {
    fn default() -> Self {
        Self::new()
    }
}

/// Split an optional section into its SVMA range and its bytes.
fn split(section: Option<SectionData>) -> (Option<Range<u64>>, Option<Sections>) {
    match section {
        Some(s) => (Some(s.svma), Some(s.bytes)),
        None => (None, None),
    }
}

/// Build architecture-native unwind registers from the neutral [`InitialRegs`].
#[cfg(target_arch = "x86_64")]
fn native_regs(regs: &InitialRegs) -> UnwindRegsNative {
    framehop::x86_64::UnwindRegsX86_64::new(regs.pc, regs.sp, regs.fp)
}

/// Build architecture-native unwind registers from the neutral [`InitialRegs`].
#[cfg(target_arch = "aarch64")]
fn native_regs(regs: &InitialRegs) -> UnwindRegsNative {
    framehop::aarch64::UnwindRegsAarch64::new(regs.lr, regs.sp, regs.fp)
}

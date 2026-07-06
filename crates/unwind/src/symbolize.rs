//! Address symbolization via [`addr2line`].
//!
//! Each module gets an [`addr2line::Loader`] over its object file. Lookups
//! convert an AVMA to the module's SVMA (`avma - base_avma`) and expand inlined
//! functions, so one machine address can yield several logical frames.

use std::ops::Range;
use std::path::Path;

use addr2line::Loader;

use crate::{elf, UnwindError};

/// One resolved stack frame.
#[derive(Debug, Clone)]
pub struct SymbolizedFrame {
    /// Demangled function name, if known.
    pub function: Option<String>,
    /// Source file path, if known.
    pub file: Option<String>,
    /// Source line number, if known.
    pub line: Option<u32>,
    /// The AVMA this frame was resolved from.
    pub address: u64,
}

/// A loaded module and the loader that symbolizes it.
struct SymModule {
    base_avma: u64,
    avma_range: Range<u64>,
    loader: Loader,
}

/// Resolves AVMAs to functions/files/lines across a set of modules.
pub struct Symbolizer {
    modules: Vec<SymModule>,
}

impl Symbolizer {
    /// Create an empty symbolizer with no modules loaded.
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
        }
    }

    /// Register a module loaded at `mapping_base` for symbolization.
    ///
    /// The same `mapping_base` passed to [`StackUnwinder::add_module`] must be
    /// used here so both agree on the AVMA -> SVMA conversion.
    ///
    /// [`StackUnwinder::add_module`]: crate::StackUnwinder::add_module
    pub fn add_module(&mut self, path: &Path, mapping_base: u64) -> Result<(), UnwindError> {
        let (base_avma, avma_range) = elf::module_bounds(path, mapping_base)?;
        let loader = Loader::new(path).map_err(|e| UnwindError::Symbol(e.to_string()))?;
        self.modules.push(SymModule {
            base_avma,
            avma_range,
            loader,
        });
        Ok(())
    }

    /// Resolve one AVMA to its (possibly inlined) frames.
    ///
    /// Returns an empty vector if no module covers the address. If DWARF yields
    /// nothing, falls back to the symbol table so at least a raw name surfaces.
    pub fn resolve(&self, avma: u64) -> Vec<SymbolizedFrame> {
        let Some(module) = self.modules.iter().find(|m| m.avma_range.contains(&avma)) else {
            return Vec::new();
        };
        let svma = avma - module.base_avma;

        let mut frames = Vec::new();
        if let Ok(mut iter) = module.loader.find_frames(svma) {
            while let Ok(Some(frame)) = iter.next() {
                let function = frame
                    .function
                    .as_ref()
                    .and_then(|name| name.demangle().ok())
                    .map(|name| name.into_owned());
                let (file, line) = match &frame.location {
                    Some(location) => (location.file.map(str::to_string), location.line),
                    None => (None, None),
                };
                frames.push(SymbolizedFrame {
                    function,
                    file,
                    line,
                    address: avma,
                });
            }
        }

        if frames.is_empty() {
            frames.push(SymbolizedFrame {
                function: module.loader.find_symbol(svma).map(str::to_string),
                file: None,
                line: None,
                address: avma,
            });
        }
        frames
    }
}

impl Default for Symbolizer {
    fn default() -> Self {
        Self::new()
    }
}

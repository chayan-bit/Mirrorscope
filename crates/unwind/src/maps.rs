//! Enumerate a live process's loaded modules from `/proc/<pid>/maps`.
//!
//! Replay uses this to feed [`StackUnwinder::add_module`] and
//! [`Symbolizer::add_module`]. The line parser [`parse_maps`] is pure and
//! platform-independent so it can be unit-tested anywhere; the `/proc` readers
//! are Linux-only.
//!
//! [`StackUnwinder::add_module`]: crate::StackUnwinder::add_module
//! [`Symbolizer::add_module`]: crate::Symbolizer::add_module

/// A file-backed module and its load address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleMapping {
    /// Absolute path of the mapped ELF file.
    pub path: String,
    /// Load address: the start AVMA of this file's `offset == 0` mapping, which
    /// maps the ELF header and anchors the load bias.
    pub base: u64,
}

/// Parse the contents of a `/proc/<pid>/maps` file.
///
/// Returns one [`ModuleMapping`] per distinct file-backed path, keyed to the
/// mapping whose file offset is `0` (the ELF header). Anonymous and pseudo
/// mappings (`[heap]`, `[stack]`, `[vdso]`, ...) are ignored. Parsing is
/// defensive: malformed lines are skipped rather than propagated.
pub fn parse_maps(content: &str) -> Vec<ModuleMapping> {
    let mut modules: Vec<ModuleMapping> = Vec::new();
    for line in content.lines() {
        let Some((path, base)) = parse_line(line) else {
            continue;
        };
        match modules.iter_mut().find(|m| m.path == path) {
            Some(existing) => existing.base = existing.base.min(base),
            None => modules.push(ModuleMapping { path, base }),
        }
    }
    modules
}

/// Parse one maps line into `(path, start)` if it is a file-backed, offset-0
/// mapping; otherwise `None`.
fn parse_line(line: &str) -> Option<(String, u64)> {
    let mut fields = line.split_whitespace();
    let addr_range = fields.next()?;
    let _perms = fields.next()?;
    let offset = fields.next()?;
    let _dev = fields.next()?;
    let _inode = fields.next()?;
    let path = fields.collect::<Vec<_>>().join(" ");

    if !path.starts_with('/') {
        return None;
    }
    if u64::from_str_radix(offset, 16).ok()? != 0 {
        return None;
    }
    let start_hex = addr_range.split('-').next()?;
    let start = u64::from_str_radix(start_hex, 16).ok()?;
    Some((path, start))
}

/// Read and parse `/proc/<pid>/maps` for the given process id.
#[cfg(target_os = "linux")]
pub fn read_process_modules(pid: u32) -> std::io::Result<Vec<ModuleMapping>> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    Ok(parse_maps(&content))
}

/// Read and parse `/proc/self/maps` for the current process.
#[cfg(target_os = "linux")]
pub fn read_self_modules() -> std::io::Result<Vec<ModuleMapping>> {
    let content = std::fs::read_to_string("/proc/self/maps")?;
    Ok(parse_maps(&content))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
55e6c0e2a000-55e6c0e2b000 r--p 00000000 08:01 100  /usr/bin/app
55e6c0e2b000-55e6c0e2f000 r-xp 00001000 08:01 100  /usr/bin/app
7f0000000000-7f0000021000 r--p 00000000 08:01 200  /lib/libc.so.6
7f0000021000-7f00000a5000 r-xp 00021000 08:01 200  /lib/libc.so.6
7ffca1b2c000-7ffca1b4d000 rw-p 00000000 00:00 0    [stack]
7ffca1bd0000-7ffca1bd4000 r-xp 00000000 00:00 0    [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0  [vsyscall]";

    #[test]
    fn keeps_one_entry_per_file_at_its_offset_zero_base() {
        let modules = parse_maps(SAMPLE);
        assert_eq!(
            modules,
            vec![
                ModuleMapping {
                    path: "/usr/bin/app".to_string(),
                    base: 0x55e6c0e2a000,
                },
                ModuleMapping {
                    path: "/lib/libc.so.6".to_string(),
                    base: 0x7f0000000000,
                },
            ]
        );
    }

    #[test]
    fn ignores_anonymous_and_pseudo_mappings() {
        let modules = parse_maps(SAMPLE);
        assert!(modules.iter().all(|m| m.path.starts_with('/')));
        assert!(!modules.iter().any(|m| m.path.contains("stack")));
        assert!(!modules.iter().any(|m| m.path.contains("vdso")));
    }

    #[test]
    fn skips_mappings_without_an_offset_zero_entry() {
        // Only a non-zero-offset mapping is present: no reliable load base.
        let only_exec = "7f0000021000-7f00000a5000 r-xp 00021000 08:01 200  /lib/only.so";
        assert!(parse_maps(only_exec).is_empty());
    }

    #[test]
    fn takes_the_lowest_start_when_offset_zero_repeats() {
        let repeated = "\
0000000000020000-0000000000021000 r--p 00000000 08:01 5  /lib/x.so
0000000000010000-0000000000011000 r--p 00000000 08:01 5  /lib/x.so";
        assert_eq!(parse_maps(repeated)[0].base, 0x10000);
    }

    #[test]
    fn skips_malformed_lines() {
        assert!(parse_maps("garbage\n\nnot a maps line").is_empty());
    }

    #[test]
    fn handles_paths_containing_spaces() {
        let spaced = "10000-11000 r--p 00000000 08:01 5  /opt/my app/bin";
        assert_eq!(parse_maps(spaced)[0].path, "/opt/my app/bin");
    }
}

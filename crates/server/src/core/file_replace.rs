//! Cross-platform atomic replacement for already-published files.

use std::path::Path;

#[cfg(windows)]
fn replace_existing_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;

    let destination_wide = destination
        .as_os_str()
        .encode_wide()
        .chain(once(0))
        .collect::<Vec<_>>();
    let source_wide = source
        .as_os_str()
        .encode_wide()
        .chain(once(0))
        .collect::<Vec<_>>();
    let replaced = unsafe {
        ReplaceFileW(
            destination_wide.as_ptr(),
            source_wide.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if replaced == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Publish source at destination, replacing an existing regular file atomically.
///
/// On Windows, rename cannot replace an existing destination, so fall back to
/// ReplaceFileW. If the destination disappears during that transition, retry a
/// normal rename. Callers keep source and destination on the same filesystem.
#[cfg(windows)]
pub(crate) fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    match std::fs::rename(source, destination) {
        Ok(()) => Ok(()),
        Err(rename_error) if destination.exists() => {
            match replace_existing_file(source, destination) {
                Ok(()) => Ok(()),
                Err(replace_error) if replace_error.kind() == std::io::ErrorKind::NotFound => {
                    std::fs::rename(source, destination)
                }
                Err(replace_error) => Err(replace_error),
            }
        }
        Err(rename_error) => Err(rename_error),
    }
}

#[cfg(not(windows))]
pub(crate) fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

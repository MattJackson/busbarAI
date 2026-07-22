// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Platform staging for loading VERIFIED library bytes - the "bytes verified == bytes loaded"
//! (TOCTOU-safe) half of the loader.
//!
//! - **Linux**: `memfd_create` - the verified bytes are written to an anonymous in-memory fd and
//!   `dlopen`ed via `/proc/self/fd/N`. ZERO disk files, nothing to sweep, nothing to swap.
//! - **macOS / Windows** (and any non-Linux unix): the verified bytes are written to a file inside
//!   a PER-PROCESS private staging directory (`<temp>/busbar-plugins-<pid>-<random>`, `0700` on
//!   unix, created exactly once per process) and loaded from there. On clean shutdown the library
//!   is unloaded FIRST, then the file (and, when empty, the directory) is removed - the order
//!   Windows requires, since a mapped DLL's file cannot be deleted. A crash leaves the directory
//!   behind; [`sweep_dead_staging`] removes any `busbar-plugins-<pid>-*` directory whose pid is no
//!   longer alive at the next boot.
//!
//! A pre-existing on-disk library is NEVER loaded: staging always regenerates the file from the
//! verified in-memory bytes; anything on disk is throwaway output, never trusted input.

use libloading::Library;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// Prefix for the per-process private staging directory (and the dead-pid sweep match).
const STAGING_PREFIX: &str = "busbar-plugins-";

/// The staged backing that must outlive the loaded [`Library`]. Dropping it releases the staging
/// resource: the memfd closes (Linux), or the private temp file is removed (and its directory, when
/// this was the last staged file). It MUST be declared AFTER the `Library` in any holder struct so
/// the library unloads first (Rust drops fields in declaration order).
pub(crate) enum Staged {
    /// Linux memfd: the anonymous fd holding the library bytes. Kept open for the library's whole
    /// life (the dlopen'd mapping does not need it, but holding it is free and unambiguous).
    #[cfg(target_os = "linux")]
    Memfd { _fd: std::os::fd::OwnedFd },
    /// A file inside the per-process private staging directory (non-Linux, or Linux memfd
    /// fallback). Removed on drop; the (shared, per-process) directory is removed too once empty.
    TempFile { path: PathBuf },
}

impl Drop for Staged {
    fn drop(&mut self) {
        match self {
            #[cfg(target_os = "linux")]
            Staged::Memfd { .. } => {} // the OwnedFd closes itself
            Staged::TempFile { path } => {
                // Unload happened first (field order in the holder). Release under the shared
                // staging lock: remove the file, and remove the per-process directory only when
                // this was the LAST live staged file - the refcount makes release atomic with any
                // concurrent stage, so a drop can never yank the directory out from under a load.
                release_temp_file(path);
            }
        }
    }
}

/// Hex-encode `n` random bytes from the OS RNG (staging-dir suffix: a pid alone is predictable).
fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    // A failed RNG read falls back to zeroes; exclusivity still comes from `create_dir` failing
    // closed on an existing path, entropy only adds unpredictability.
    let _ = getrandom::fill(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Shared staging state: the per-process private directory (created lazily, re-created if the
/// last release removed it) plus a LIVE-FILE REFCOUNT. All creates and releases run under this one
/// lock, so "remove the dir when the last staged file goes" can never race a concurrent stage.
struct StagingState {
    dir: Option<PathBuf>,
    live: usize,
}

fn staging_state() -> &'static Mutex<StagingState> {
    static STATE: OnceLock<Mutex<StagingState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(StagingState { dir: None, live: 0 }))
}

/// Ensure the per-process private staging directory exists (caller holds the staging lock):
/// `<temp>/busbar-plugins-<pid>-<random>`, mode `0700` on unix. `create_dir` (not
/// `create_dir_all`) fails if the path already exists, so a pre-planted directory is never adopted.
fn ensure_staging_dir(state: &mut StagingState) -> Result<PathBuf, String> {
    if let Some(dir) = &state.dir {
        if dir.is_dir() {
            return Ok(dir.clone());
        }
    }
    let name = format!("{STAGING_PREFIX}{}-{}", std::process::id(), random_hex(8));
    let dir = std::env::temp_dir().join(name);
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(&dir).map_err(|e| {
        format!(
            "cannot create private plugin staging dir {}: {e}",
            dir.display()
        )
    })?;
    state.dir = Some(dir.clone());
    Ok(dir)
}

/// Release one staged file (drop path): remove the file and, when it was the LAST live one, the
/// per-process directory too (clean-shutdown delete). Runs entirely under the staging lock.
fn release_temp_file(path: &PathBuf) {
    let mut state = staging_state().lock().unwrap_or_else(|p| p.into_inner());
    let _ = std::fs::remove_file(path);
    state.live = state.live.saturating_sub(1);
    if state.live == 0 {
        if let Some(dir) = state.dir.take() {
            let _ = std::fs::remove_dir(&dir);
        }
    }
}

/// Monotonic per-process staging-file sequence (concurrent loads never collide on a name).
fn next_seq() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

/// The platform dynamic-library suffix, used only to give the staged file a plausible extension
/// (some loaders key off it). Load correctness does not depend on it.
fn dylib_suffix() -> &'static str {
    if cfg!(target_os = "windows") {
        ".dll"
    } else if cfg!(target_os = "macos") {
        ".dylib"
    } else {
        ".so"
    }
}

/// Stage `bytes` into the per-process private directory and return the created file path. The file
/// is opened `create_new` (never adopting a pre-planted file) and `0600` on unix. Runs under the
/// staging lock so a concurrent last-file release cannot remove the directory mid-create.
fn stage_temp_file(bytes: &[u8]) -> Result<PathBuf, String> {
    let mut state = staging_state().lock().unwrap_or_else(|p| p.into_inner());
    let dir = ensure_staging_dir(&mut state)?;
    let path = dir.join(format!("lib-{}{}", next_seq(), dylib_suffix()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&path)
        .map_err(|e| format!("cannot create staged plugin file {}: {e}", path.display()))?;
    if let Err(e) = f.write_all(bytes).and_then(|()| f.flush()) {
        drop(f);
        let _ = std::fs::remove_file(&path);
        return Err(format!(
            "cannot write staged plugin file {}: {e}",
            path.display()
        ));
    }
    // Close before dlopen (Windows dislikes an open writable handle racing the loader's read).
    drop(f);
    state.live += 1;
    Ok(path)
}

/// Load a dynamic library from EXACTLY the in-memory `bytes` supplied - the verified-bytes ==
/// loaded-bytes entrypoint. On Linux this uses `memfd_create` + `/proc/self/fd/N` (zero disk
/// files); elsewhere (or if memfd fails) the bytes are staged into the per-process private `0700`
/// directory and loaded from there. `display` labels errors. Returns the mapped [`Library`] plus
/// the [`Staged`] guard that must be dropped AFTER the library.
pub(crate) fn load_library_from_bytes(
    bytes: &[u8],
    display: &str,
) -> Result<(Library, Staged), String> {
    #[cfg(target_os = "linux")]
    {
        match load_via_memfd(bytes, display) {
            Ok(loaded) => return Ok(loaded),
            Err(e) => {
                // memfd requires a mounted /proc for the dlopen path; fall back to the private
                // temp-file staging (same verified bytes, weaker zero-disk property) rather than
                // fail a legitimate load on an exotic mount setup.
                eprintln!(
                    "[warn] memfd load unavailable for plugin '{display}' ({e}); falling back to \
                     private temp staging"
                );
            }
        }
    }
    let path = stage_temp_file(bytes)?;
    // SAFETY: running an operator-trusted plugin's init code - the same trust as compiling it in.
    // The file was created by us, in a directory we created 0700, from already-verified bytes.
    let lib = unsafe { Library::new(&path) }.map_err(|e| {
        let msg = format!("failed to load plugin '{display}': {e}");
        let _ = std::fs::remove_file(&path);
        msg
    })?;
    Ok((lib, Staged::TempFile { path }))
}

/// Linux zero-disk load: write the verified bytes to an anonymous memfd and dlopen it via
/// `/proc/self/fd/N`. Nothing ever touches the filesystem.
#[cfg(target_os = "linux")]
fn load_via_memfd(bytes: &[u8], display: &str) -> Result<(Library, Staged), String> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    // SAFETY: plain syscall; the name is a debugging label (NUL-terminated, no user input).
    let raw = unsafe { libc::memfd_create(c"busbar-plugin".as_ptr(), libc::MFD_CLOEXEC) };
    if raw < 0 {
        return Err(format!(
            "memfd_create failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `raw` is a freshly created, owned fd.
    let fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(raw) };
    {
        let mut f = std::fs::File::from(fd.try_clone().map_err(|e| format!("memfd dup: {e}"))?);
        f.write_all(bytes)
            .and_then(|()| f.flush())
            .map_err(|e| format!("memfd write: {e}"))?;
    }
    let path = format!("/proc/self/fd/{}", fd.as_raw_fd());
    // SAFETY: same operator-trust as any plugin load; the fd content is exactly the verified bytes
    // and is not reachable by path from any other process's namespace.
    let lib = unsafe { Library::new(&path) }
        .map_err(|e| format!("failed to load plugin '{display}' from memfd: {e}"))?;
    Ok((lib, Staged::Memfd { _fd: fd }))
}

/// Is the process with `pid` alive? Unix: `kill(pid, 0)` (EPERM still means alive). Non-unix:
/// unknown - report alive so the sweep stays conservative (Windows removal of a live dir fails
/// naturally on the locked DLL anyway).
fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid_i) = i32::try_from(pid) else {
            return false;
        };
        // SAFETY: signal 0 performs error checking only; no signal is delivered.
        let rc = unsafe { libc::kill(pid_i, 0) };
        rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

/// BOOT-TIME sweep of orphaned staging directories: any `busbar-plugins-<pid>-*` under the temp
/// base whose pid is DEAD (a prior busbar crashed before its clean-shutdown cleanup) is removed -
/// the files are unlocked once the process died. The current process's own directory and any
/// live process's directory are left alone. Returns the number of directories removed.
pub fn sweep_dead_staging() -> usize {
    let base = std::env::temp_dir();
    let mut removed = 0usize;
    let Ok(entries) = std::fs::read_dir(&base) else {
        return 0;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(rest) = name.strip_prefix(STAGING_PREFIX) else {
            continue;
        };
        // `<pid>-<random>`: parse the pid segment.
        let Some(pid) = rest.split('-').next().and_then(|p| p.parse::<u32>().ok()) else {
            continue;
        };
        if pid == std::process::id() || pid_alive(pid) {
            continue;
        }
        if entry.path().is_dir() && std::fs::remove_dir_all(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The per-process staging dir is private (0700 on unix), named with the pid, and stable
    /// while staged files are live.
    #[test]
    fn staging_dir_is_private_and_pid_named() {
        let mut state = staging_state().lock().unwrap_or_else(|p| p.into_inner());
        let dir = ensure_staging_dir(&mut state).expect("staging dir");
        assert!(dir.exists());
        let name = dir.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with(STAGING_PREFIX));
        assert!(name.contains(&std::process::id().to_string()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "staging dir must be 0700, got {mode:o}");
        }
        // A second call returns the SAME directory while it exists.
        assert_eq!(ensure_staging_dir(&mut state).unwrap(), dir);
    }

    /// Dropping a `Staged::TempFile` removes the file (unload-then-remove is enforced by holder
    /// field order; here we assert the removal half).
    #[test]
    fn temp_file_staging_cleans_up_on_drop() {
        let path = stage_temp_file(b"pretend library bytes").expect("stage");
        assert!(path.exists());
        drop(Staged::TempFile { path: path.clone() });
        assert!(!path.exists(), "staged file must be removed on drop");
    }

    /// The dead-pid sweep removes a staging dir whose pid is dead, and leaves the live (current)
    /// process's dir alone.
    #[test]
    fn sweep_removes_dead_pid_dirs_only() {
        // A dir for a pid that is certainly dead (pid_max on linux is < 2^22 by default; u32::MAX
        // range pids do not exist on any supported platform).
        let dead = std::env::temp_dir().join(format!("{STAGING_PREFIX}4294967294-deadbeef"));
        let _ = std::fs::remove_dir_all(&dead);
        std::fs::create_dir_all(dead.join("sub")).unwrap();
        std::fs::write(dead.join("sub/lib.so"), b"junk").unwrap();

        // Our own live dir must survive the sweep: hold a real staged file so the shared state
        // keeps the directory alive for the duration of this test.
        let held = Staged::TempFile {
            path: stage_temp_file(b"keepalive bytes").expect("stage keepalive"),
        };
        let own = {
            let state = staging_state().lock().unwrap_or_else(|p| p.into_inner());
            state
                .dir
                .clone()
                .expect("staging dir exists while a file is live")
        };

        let removed = sweep_dead_staging();
        assert!(removed >= 1, "the dead-pid dir must be swept");
        assert!(!dead.exists(), "dead-pid staging dir removed");
        assert!(
            own.exists(),
            "own (live-pid) staging dir survives the sweep"
        );
        drop(held);
    }

    /// pid_alive is true for ourselves and false for an absurd pid (unix).
    #[cfg(unix)]
    #[test]
    fn pid_liveness() {
        assert!(pid_alive(std::process::id()));
        assert!(!pid_alive(4_294_967_294));
    }
}

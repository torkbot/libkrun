// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::btree_map;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::ptr::null_mut;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crossbeam_channel::{Sender, unbounded};
use nix::errno::Errno;
use utils::worker_message::WorkerMessage;

use crate::virtio::fs::filesystem::SecContext;

use super::super::super::linux_errno::{LINUX_EOPNOTSUPP, LINUX_ERANGE, linux_error};
use super::super::bindings;
use super::super::filesystem::{
    Context, DirEntry, Entry, ExportTable, Extensions, FileSystem, FsOptions, GetxattrReply,
    ListxattrReply, OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};
use super::super::fuse;
use super::super::inode_alloc::InodeAllocator;
use super::super::multikey::MultikeyBTreeMap;
pub use super::sandbox_metadata::IdentityMapping;
use super::sandbox_metadata::{
    GuestMetadata, NameError, OVERFLOW_ID, XATTR_NAME_C, guest_name_from_carrier,
    user_xattr_host_name, validate_capability,
};

#[derive(Debug, Clone, Copy)]
pub struct SandboxConfig {
    pub identity: IdentityMapping,
    pub xattrs_enabled: bool,
}

const XATTR_KEY: &[u8] = b"user.containers.override_stat\0";
const SECURITY_CAPABILITY: &[u8] = b"security.capability\0";

const MACOS_XATTR_PREFIX: &[u8] = b"com.apple.";

const UID_MAX: u32 = u32::MAX - 1;

type Inode = u64;
type Handle = u64;

#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
struct InodeAltKey {
    ino: u64,
    dev: i32,
}

struct InodeData {
    inode: Inode,
    ino: u64,
    dev: i32,
    refcount: AtomicU64,
    unlinked_fd: AtomicI64,
}

enum InodeHandle {
    Fd(RawFd),
    Path(CString),
}

struct CachedDirEntry {
    ino: bindings::ino64_t,
    name: Box<[u8]>,
    type_: u8,
}

struct DirStream {
    entries: Vec<CachedDirEntry>,
    ready: bool,
}

impl DirStream {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            ready: false,
        }
    }

    fn get_entry<'a>(&'a self, offset: u64) -> Option<DirEntry<'a>> {
        self.entries.get(offset as usize).map(|e| DirEntry {
            ino: e.ino,
            // offset points to the next entry, not the current one
            offset: offset + 1,
            type_: u32::from(e.type_),
            name: &e.name,
        })
    }

    fn fill_from_fd(&mut self, fd: RawFd) -> io::Result<()> {
        // fdopendir() takes ownership of the fd, so we need to obtain a new one
        // to be donated.
        let newfd = unsafe { libc::dup(fd) };
        if newfd < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }
        let dir = unsafe { libc::fdopendir(newfd) };
        if dir.is_null() {
            let err = io::Error::last_os_error();
            let _ = unsafe { libc::close(newfd) };
            return Err(linux_error(err));
        }

        loop {
            // To detect if error happened in readdir we should clear errno
            // before the call and then verify it after
            Errno::clear();
            let dentry = unsafe { libc::readdir(dir) };
            if dentry.is_null() {
                let errno = Errno::last_raw();
                if errno != 0 {
                    let err = io::Error::from_raw_os_error(errno);
                    let _ = unsafe { libc::closedir(dir) };
                    // Error happened in readdir, but we keep the entries we
                    // already read to handle the partial read.
                    return Err(linux_error(err));
                }
                break;
            }
            // SAFETY: dentry is not null.
            // We trust macOS to return correct number of bytes for the name
            // length. The lifetime of a slice does not escape the unsafe block
            // as we copy the data into box right away.
            let name = unsafe {
                let name_len = usize::from((*dentry).d_namlen);
                let name_ptr = (*dentry).d_name.as_ptr().cast();
                let name = std::slice::from_raw_parts(name_ptr, name_len);

                if name == b"." || name == b".." {
                    continue;
                }
                Box::<[u8]>::from(name)
            };

            // SAFETY: dentry is not null.
            let ino = unsafe { (*dentry).d_ino };
            // SAFETY: dentry is not null. The entry types use the same
            // exact constants (`libc::DT_*`) on macOS, Linux, and FUSE.
            let type_ = unsafe { (*dentry).d_type };

            self.entries.push(CachedDirEntry { ino, name, type_ });
        }

        unsafe { libc::closedir(dir) };
        Ok(())
    }
}

struct HandleData {
    inode: Inode,
    file: RwLock<File>,
    dirstream: Mutex<DirStream>,
}

fn ebadf() -> io::Error {
    linux_error(io::Error::from_raw_os_error(libc::EBADF))
}

fn einval() -> io::Error {
    linux_error(io::Error::from_raw_os_error(libc::EINVAL))
}

fn item_to_value(item: &[u8], radix: u32) -> Option<u32> {
    match std::str::from_utf8(item) {
        Ok(val) => match u32::from_str_radix(val, radix) {
            Ok(i) => Some(i),
            Err(e) => {
                debug!("invalid value: {radix} err={e}");
                None
            }
        },
        Err(_) => None,
    }
}

fn get_xattr_common(buf: &[u8]) -> io::Result<(Option<u32>, Option<u32>, Option<u32>)> {
    let mut items = buf.split(|c| *c == b':');

    let uid = match items.next() {
        Some(item) => item_to_value(item, 10),
        None => None,
    };
    let gid = match items.next() {
        Some(item) => item_to_value(item, 10),
        None => None,
    };
    let mode = match items.next() {
        Some(item) => item_to_value(item, 8),
        None => None,
    };

    Ok((uid, gid, mode))
}

fn get_xattr_fstat(
    fd: RawFd,
    st: bindings::stat64,
) -> io::Result<(Option<u32>, Option<u32>, Option<u32>)> {
    let mut buf: Vec<u8> = vec![0; 32];
    let options = if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
        libc::XATTR_NOFOLLOW
    } else {
        0
    };
    let res = unsafe {
        libc::fgetxattr(
            fd,
            XATTR_KEY.as_ptr() as *const i8,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            options,
        )
    };
    if res < 0 {
        debug!("fget_xattr error: {res}");
        return Ok((None, None, None));
    }

    buf.resize(res as usize, 0);

    get_xattr_common(&buf)
}

fn get_xattr_lstat(
    path: &CString,
    st: bindings::stat64,
) -> io::Result<(Option<u32>, Option<u32>, Option<u32>)> {
    let mut buf: Vec<u8> = vec![0; 32];
    let options = if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
        libc::XATTR_NOFOLLOW
    } else {
        0
    };
    let res = unsafe {
        libc::getxattr(
            path.as_ptr(),
            XATTR_KEY.as_ptr() as *const i8,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            options,
        )
    };
    if res < 0 {
        debug!("fget_xattr error: {res}");
        return Ok((None, None, None));
    }

    buf.resize(res as usize, 0);

    get_xattr_common(&buf)
}

fn is_valid_owner(owner: Option<(u32, u32)>) -> bool {
    if let Some(owner) = owner
        && owner.0 < UID_MAX
        && owner.1 < UID_MAX
    {
        return true;
    }

    false
}

// We won't need this once expressions like "if let ... &&" are allowed.
#[allow(clippy::unnecessary_unwrap)]
fn set_xattr_stat(
    ctx: &Context,
    file: &InodeHandle,
    st: Option<bindings::stat64>,
    owner: Option<(u32, u32)>,
    mode: Option<u32>,
) -> io::Result<()> {
    let st = st.unwrap_or(istat(ctx, PermissionSemantics::LinuxComplete, file, true)?);
    let options = if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
        libc::XATTR_NOFOLLOW
    } else {
        0
    };

    let buf = if is_valid_owner(owner) && mode.is_some() {
        let owner = owner.unwrap();
        let mode = mode.unwrap();
        format!("{}:{}:0{:o}", owner.0, owner.1, mode)
    } else {
        let (orig_uid, orig_gid, orig_mode) = match file {
            InodeHandle::Fd(fd) => get_xattr_fstat(*fd, st)?,
            InodeHandle::Path(c_path) => get_xattr_lstat(c_path, st)?,
        };

        let (uid, gid) = match owner {
            Some(o) => {
                let uid = if o.0 < UID_MAX { Some(o.0) } else { orig_uid };
                let gid = if o.1 < UID_MAX { Some(o.1) } else { orig_gid };
                (uid, gid)
            }
            None => (orig_uid, orig_gid),
        };

        let mut buf = String::new();
        if let Some(uid) = uid {
            buf.push_str(&format!("{uid}"));
        } else {
            buf.push('x');
        }
        if let Some(gid) = gid {
            buf.push_str(&format!(":{gid}:"));
        } else {
            buf.push_str(":x:");
        }
        if let Some(mode) = mode {
            buf.push_str(&format!("0{:o}", mode));
        } else if let Some(orig_mode) = orig_mode {
            buf.push_str(&format!("0{:o}", orig_mode));
        } else {
            buf.push('x');
        }
        buf
    };

    let res = match file {
        InodeHandle::Path(path) => unsafe {
            libc::setxattr(
                path.as_ptr(),
                XATTR_KEY.as_ptr() as *const i8,
                buf.as_ptr() as *mut libc::c_void,
                buf.len() as libc::size_t,
                0,
                options,
            )
        },
        InodeHandle::Fd(fd) => unsafe {
            libc::fsetxattr(
                *fd,
                XATTR_KEY.as_ptr() as *const i8,
                buf.as_ptr() as *mut libc::c_void,
                buf.len() as libc::size_t,
                0,
                options,
            )
        },
    };

    if res < 0 {
        Err(linux_error(io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

fn set_host_stat(
    file: &InodeHandle,
    _owner: Option<(u32, u32)>,
    mode: Option<u32>,
) -> io::Result<()> {
    // We're only using set_host_stat for LinuxSimplified semantics, and in this
    // mode we ignore the host's owner bits, so don't attempt to write them here.

    if let Some(mode) = mode {
        let res = match file {
            InodeHandle::Path(path) => unsafe { libc::chmod(path.as_ptr(), mode as u16) },
            InodeHandle::Fd(fd) => unsafe { libc::fchmod(*fd, mode as u16) },
        };

        if res < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }
    }

    Ok(())
}

fn sandbox_xattr_options(st: bindings::stat64) -> i32 {
    if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
        libc::XATTR_NOFOLLOW
    } else {
        0
    }
}

fn sandbox_xattr_options_for_handle(file: &InodeHandle, st: bindings::stat64) -> i32 {
    match file {
        InodeHandle::Path(_) => sandbox_xattr_options(st),
        // An fd already identifies the symlink itself when opened with
        // O_SYMLINK; XATTR_NOFOLLOW is a pathname-only option on macOS.
        InodeHandle::Fd(_) => 0,
    }
}

fn read_sandbox_metadata(
    file: &InodeHandle,
    st: bindings::stat64,
) -> io::Result<Option<GuestMetadata>> {
    // Attribute-not-found is the only state that means "native". In
    // particular, malformed or unreadable adopted metadata must never fall
    // back to host stat and silently change the guest's authority view.
    let options = sandbox_xattr_options_for_handle(file, st);
    loop {
        let size = match file {
            InodeHandle::Path(path) => unsafe {
                libc::getxattr(
                    path.as_ptr(),
                    XATTR_NAME_C.as_ptr().cast(),
                    null_mut(),
                    0,
                    0,
                    options,
                )
            },
            InodeHandle::Fd(fd) => unsafe {
                libc::fgetxattr(*fd, XATTR_NAME_C.as_ptr().cast(), null_mut(), 0, 0, options)
            },
        };
        if size < 0 {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ENOATTR) {
                Ok(None)
            } else {
                Err(linux_error(error))
            };
        }

        let mut value = vec![0; size as usize];
        let read = match file {
            InodeHandle::Path(path) => unsafe {
                libc::getxattr(
                    path.as_ptr(),
                    XATTR_NAME_C.as_ptr().cast(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                    0,
                    options,
                )
            },
            InodeHandle::Fd(fd) => unsafe {
                libc::fgetxattr(
                    *fd,
                    XATTR_NAME_C.as_ptr().cast(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                    0,
                    options,
                )
            },
        };
        if read < 0 {
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::ERANGE) => continue,
                Some(libc::ENOATTR) => return Ok(None),
                _ => return Err(linux_error(error)),
            }
        }
        value.truncate(read as usize);
        let metadata = GuestMetadata::parse(&value).map_err(|_| einval())?;
        if !metadata.matches_file_kind(st.st_mode as u32) {
            return Err(einval());
        }
        return Ok(Some(metadata));
    }
}

fn read_sandbox_metadata_for_config(
    file: &InodeHandle,
    st: bindings::stat64,
    config: SandboxConfig,
) -> io::Result<Option<GuestMetadata>> {
    match read_sandbox_metadata(file, st) {
        Err(error) if !config.xattrs_enabled && error.raw_os_error() == Some(LINUX_EOPNOTSUPP) => {
            // Native-only mode is selected only for a backing volume that
            // reports no xattr support. Still attempt the read so an adopted
            // record can never be silently ignored if a caller supplies a
            // stale or incorrect capability result.
            Ok(None)
        }
        result => result,
    }
}

fn write_sandbox_metadata(
    file: &InodeHandle,
    st: bindings::stat64,
    metadata: &GuestMetadata,
) -> io::Result<()> {
    if !metadata.matches_file_kind(st.st_mode as u32) {
        return Err(einval());
    }
    let value = metadata.encode();
    let options = sandbox_xattr_options_for_handle(file, st);
    let result = match file {
        InodeHandle::Path(path) => unsafe {
            libc::setxattr(
                path.as_ptr(),
                XATTR_NAME_C.as_ptr().cast(),
                value.as_ptr().cast(),
                value.len(),
                0,
                options,
            )
        },
        InodeHandle::Fd(fd) => unsafe {
            libc::fsetxattr(
                *fd,
                XATTR_NAME_C.as_ptr().cast(),
                value.as_ptr().cast(),
                value.len(),
                0,
                options,
            )
        },
    };
    if result == 0 {
        Ok(())
    } else {
        Err(linux_error(io::Error::last_os_error()))
    }
}

fn set_sandbox_stat(
    ctx: &Context,
    config: SandboxConfig,
    file: &InodeHandle,
    host_st: Option<bindings::stat64>,
    owner: Option<(u32, u32)>,
    mode: Option<u32>,
) -> io::Result<()> {
    update_sandbox_metadata(ctx, config, file, host_st, owner, mode, false, false, true)
}

#[allow(clippy::too_many_arguments)]
fn update_sandbox_metadata(
    ctx: &Context,
    config: SandboxConfig,
    file: &InodeHandle,
    host_st: Option<bindings::stat64>,
    owner: Option<(u32, u32)>,
    mode: Option<u32>,
    clear_capability: bool,
    clear_mode_privileges: bool,
    persist_unchanged_metadata: bool,
) -> io::Result<()> {
    // Fs currently dispatches one request queue through one synchronous
    // worker. That serialization makes this read-modify-replace operation a
    // POSIX-ordered metadata transition. If dispatch becomes parallel, the
    // worker boundary must add same-inode serialization before this remains
    // safe; a second lock here would only duplicate the current owner.
    let mapping = config.identity;
    let host_st = host_st.unwrap_or(istat(
        ctx,
        PermissionSemantics::Sandbox(config),
        file,
        true,
    )?);
    let existing = read_sandbox_metadata_for_config(file, host_st, config)?;
    let mut metadata = existing.clone().unwrap_or_else(|| {
        GuestMetadata::from_native(
            mapping,
            host_st.st_uid,
            host_st.st_gid,
            host_st.st_mode as u32,
        )
    });
    let original = metadata.clone();
    if let Some((uid, gid)) = owner {
        if uid != u32::MAX {
            metadata.uid = uid;
        }
        if gid != u32::MAX {
            metadata.gid = gid;
        }
    }
    if let Some(mode) = mode {
        let requested_kind = mode & libc::S_IFMT as u32;
        let current_kind = metadata.mode & libc::S_IFMT as u32;
        if requested_kind != 0 && requested_kind != current_kind {
            return Err(einval());
        }
        metadata.mode = current_kind | (mode & !(libc::S_IFMT as u32));
    }
    if clear_capability {
        metadata.capability = None;
    }
    if clear_mode_privileges {
        metadata.mode = clear_suid_sgid(metadata.mode);
    }
    if existing.is_none()
        && metadata == original
        && (!persist_unchanged_metadata || !config.xattrs_enabled)
    {
        return Ok(());
    }
    if !config.xattrs_enabled && existing.is_none() {
        // Native-only entries remain writable while no guest metadata must
        // change, but a transition that needs an authority record fails
        // closed instead of mutating host ownership or mode.
        return Err(linux_error(io::Error::from_raw_os_error(libc::EOPNOTSUPP)));
    }
    write_sandbox_metadata(file, host_st, &metadata)
}

fn prepare_sandbox_content_mutation(
    ctx: &Context,
    config: SandboxConfig,
    file: &InodeHandle,
    clear_mode_privileges: bool,
) -> io::Result<()> {
    // HANDLE_KILLPRIV_V2 requires capabilities to be cleared for every write
    // or truncate. The request flag controls only whether setuid/setgid must
    // also be cleared.
    update_sandbox_metadata(
        ctx,
        config,
        file,
        None,
        None,
        None,
        true,
        clear_mode_privileges,
        false,
    )
}

fn open_sandbox_create(path: &CStr, flags: i32, mode: u32) -> io::Result<(RawFd, bool)> {
    let caller_requested_exclusive = flags & libc::O_EXCL != 0;
    let base_flags = (flags & !(libc::O_CREAT | libc::O_EXCL)) | libc::O_CLOEXEC | libc::O_NOFOLLOW;

    if caller_requested_exclusive {
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                base_flags | libc::O_CREAT | libc::O_EXCL,
                mode,
            )
        };
        return if fd >= 0 {
            Ok((fd, true))
        } else {
            Err(linux_error(io::Error::last_os_error()))
        };
    }

    loop {
        // The exclusive attempt tells us whether this request created the
        // inode, so only a newly created file receives creation metadata.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                base_flags | libc::O_CREAT | libc::O_EXCL,
                mode,
            )
        };
        if fd >= 0 {
            return Ok((fd, true));
        }
        let create_error = io::Error::last_os_error();
        if create_error.raw_os_error() != Some(libc::EEXIST) {
            return Err(linux_error(create_error));
        }

        // FUSE may issue CREATE from a cached negative lookup even if a host
        // actor populated the path in the meantime. POSIX O_CREAT without
        // O_EXCL opens that inode. If it disappears between these two calls,
        // retry until one side of the race wins.
        let fd = unsafe { libc::open(path.as_ptr(), base_flags, mode) };
        if fd >= 0 {
            return Ok((fd, false));
        }
        let open_error = io::Error::last_os_error();
        if open_error.raw_os_error() != Some(libc::ENOENT) {
            return Err(linux_error(open_error));
        }
    }
}

fn apply_sandbox_stat(
    st: &mut bindings::stat64,
    mapping: IdentityMapping,
    metadata: Option<GuestMetadata>,
) -> io::Result<bindings::stat64> {
    if let Some(metadata) = metadata {
        st.st_uid = metadata.uid;
        st.st_gid = metadata.gid;
        st.st_mode = metadata.mode as u16;
    } else {
        let kind = st.st_mode as u32 & libc::S_IFMT as u32;
        if kind != libc::S_IFREG as u32
            && kind != libc::S_IFDIR as u32
            && kind != libc::S_IFLNK as u32
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EOPNOTSUPP)));
        }
        st.st_uid = mapping.guest_uid_for(st.st_uid);
        st.st_gid = mapping.guest_gid_for(st.st_gid);
    }
    Ok(*st)
}

fn set_stat(
    ctx: &Context,
    semantics: PermissionSemantics,
    file: &InodeHandle,
    st: Option<bindings::stat64>,
    owner: Option<(u32, u32)>,
    mode: Option<u32>,
) -> io::Result<()> {
    match semantics {
        PermissionSemantics::LinuxComplete => set_xattr_stat(ctx, file, st, owner, mode),
        PermissionSemantics::LinuxSimplified => set_host_stat(file, owner, mode),
        PermissionSemantics::Sandbox(config) => {
            set_sandbox_stat(ctx, config, file, st, owner, mode)
        }
    }
}

fn stat_xattr_common(
    st: &mut bindings::stat64,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u32>,
) -> io::Result<bindings::stat64> {
    if let Some(uid) = uid {
        st.st_uid = uid;
    }
    if let Some(gid) = gid {
        st.st_gid = gid;
    }
    if let Some(mode) = mode {
        if mode as u16 & libc::S_IFMT == 0 {
            st.st_mode = (st.st_mode & libc::S_IFMT) | mode as u16;
        } else {
            st.st_mode = mode as u16;
        }
    }

    Ok(*st)
}

fn fstat(
    ctx: &Context,
    semantics: PermissionSemantics,
    fd: RawFd,
    host: bool,
) -> io::Result<bindings::stat64> {
    let mut st = MaybeUninit::<bindings::stat64>::zeroed();

    // Safe because the kernel will only write data in `st` and we check the return
    // value.
    let res = unsafe { libc::fstat(fd, st.as_mut_ptr()) };
    if res >= 0 {
        // Safe because the kernel guarantees that the struct is now fully initialized.
        let mut st = unsafe { st.assume_init() };
        if !host {
            match semantics {
                PermissionSemantics::LinuxComplete => {
                    let (uid, gid, mode) = get_xattr_fstat(fd, st)?;
                    stat_xattr_common(&mut st, uid, gid, mode)
                }
                PermissionSemantics::LinuxSimplified => {
                    st.st_uid = ctx.uid;
                    st.st_gid = ctx.gid;
                    Ok(st)
                }
                PermissionSemantics::Sandbox(config) => {
                    let metadata =
                        read_sandbox_metadata_for_config(&InodeHandle::Fd(fd), st, config)?;
                    apply_sandbox_stat(&mut st, config.identity, metadata)
                }
            }
        } else {
            Ok(st)
        }
    } else {
        Err(linux_error(io::Error::last_os_error()))
    }
}

const SANDBOX_STAT_OPEN_FLAGS: i32 =
    libc::O_EVTONLY | libc::O_SYMLINK | libc::O_NONBLOCK | libc::O_CLOEXEC;

fn open_sandbox_stat(path: &CStr) -> io::Result<File> {
    // O_EVTONLY avoids requiring file read access, while O_SYMLINK binds the
    // descriptor to a final symlink instead of following it. O_NONBLOCK keeps
    // an unsupported host FIFO from stalling the sole filesystem worker
    // before its kind can be rejected.
    let fd = unsafe { libc::open(path.as_ptr(), SANDBOX_STAT_OPEN_FLAGS) };
    if fd < 0 {
        return Err(linux_error(io::Error::last_os_error()));
    }
    // Establish RAII ownership before either fstat or xattr parsing can fail
    // so every error path closes the descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn lstat(
    ctx: &Context,
    semantics: PermissionSemantics,
    c_path: &CString,
    host: bool,
) -> io::Result<bindings::stat64> {
    if !host && let PermissionSemantics::Sandbox(_) = semantics {
        // Stat and metadata must come from the same vnode: a host actor can
        // replace a pathname between independent lstat and getxattr calls.
        let file = open_sandbox_stat(c_path)?;
        return fstat(ctx, semantics, file.as_raw_fd(), false);
    }

    let mut st = MaybeUninit::<bindings::stat64>::zeroed();

    // Safe because the kernel will only write data in `st` and we check the return
    // value.
    let res = unsafe { libc::lstat(c_path.as_ptr(), st.as_mut_ptr()) };
    if res >= 0 {
        // Safe because the kernel guarantees that the struct is now fully initialized.
        let mut st = unsafe { st.assume_init() };
        if !host {
            match semantics {
                PermissionSemantics::LinuxComplete => {
                    let (uid, gid, mode) = get_xattr_lstat(c_path, st)?;
                    stat_xattr_common(&mut st, uid, gid, mode)
                }
                PermissionSemantics::LinuxSimplified => {
                    st.st_uid = ctx.uid;
                    st.st_gid = ctx.gid;
                    Ok(st)
                }
                PermissionSemantics::Sandbox(config) => {
                    let metadata = read_sandbox_metadata_for_config(
                        &InodeHandle::Path(c_path.clone()),
                        st,
                        config,
                    )?;
                    apply_sandbox_stat(&mut st, config.identity, metadata)
                }
            }
        } else {
            Ok(st)
        }
    } else {
        Err(linux_error(io::Error::last_os_error()))
    }
}

fn istat(
    ctx: &Context,
    semantics: PermissionSemantics,
    ihandle: &InodeHandle,
    host: bool,
) -> io::Result<bindings::stat64> {
    match ihandle {
        InodeHandle::Fd(fd) => fstat(ctx, semantics, *fd, host),
        InodeHandle::Path(c_path) => lstat(ctx, semantics, c_path, host),
    }
}

/// The caching policy that the file system should report to the FUSE client. By default the FUSE
/// protocol uses close-to-open consistency. This means that any cached contents of the file are
/// invalidated the next time that file is opened.
#[derive(Debug, Default, Clone)]
pub enum CachePolicy {
    /// The client should never cache file data and all I/O should be directly forwarded to the
    /// server. This policy must be selected when file contents may change without the knowledge of
    /// the FUSE client (i.e., the file system does not have exclusive access to the directory).
    Never,

    /// The client is free to choose when and how to cache file data. This is the default policy and
    /// uses close-to-open consistency as described in the enum documentation.
    #[default]
    Auto,

    /// The client should always cache file data. This means that the FUSE client will not
    /// invalidate any cached data that was returned by the file system the last time the file was
    /// opened. This policy should only be selected when the file system has exclusive access to the
    /// directory.
    Always,
}

impl FromStr for CachePolicy {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "never" | "Never" | "NEVER" => Ok(CachePolicy::Never),
            "auto" | "Auto" | "AUTO" => Ok(CachePolicy::Auto),
            "always" | "Always" | "ALWAYS" => Ok(CachePolicy::Always),
            _ => Err("invalid cache policy"),
        }
    }
}

/// The permission semantics to be emulated by this file system personality.
#[derive(Debug, Default, Clone, Copy)]
pub enum PermissionSemantics {
    /// Be as close as possible to the common semantics of Linux file systems.
    #[default]
    LinuxComplete,

    /// As `LinuxComplete`, with the following simplifications:
    ///  - Extended attributes are not supported.
    ///  - Idmaps are not supported.
    ///  - Ownership bits are ignored, always returning the uid/gid from the process
    ///    requesting the operation within the guest (obtained from `Context`).
    ///  - Permissions bits are stored in the host, not as extended attributes.
    LinuxSimplified,

    /// Sandbox host-directory semantics. Native host ownership is translated
    /// through one VM-scoped mapping and guest-owned metadata is persisted in
    /// Sandbox's private complete record.
    Sandbox(SandboxConfig),
}

/// Options that configure the behavior of the file system.
#[derive(Debug, Clone)]
pub struct Config {
    /// How long the FUSE client should consider directory entries to be valid. If the contents of a
    /// directory can only be modified by the FUSE client (i.e., the file system has exclusive
    /// access), then this should be a large value.
    ///
    /// The default value for this option is 5 seconds.
    pub entry_timeout: Duration,

    /// How long the FUSE client should consider file and directory attributes to be valid. If the
    /// attributes of a file or directory can only be modified by the FUSE client (i.e., the file
    /// system has exclusive access), then this should be set to a large value.
    ///
    /// The default value for this option is 5 seconds.
    pub attr_timeout: Duration,

    /// The caching policy the file system should use. See the documentation of `CachePolicy` for
    /// more details.
    pub cache_policy: CachePolicy,

    /// Whether the file system should enabled writeback caching. This can improve performance as it
    /// allows the FUSE client to cache and coalesce multiple writes before sending them to the file
    /// system. However, enabling this option can increase the risk of data corruption if the file
    /// contents can change without the knowledge of the FUSE client (i.e., the server does **NOT**
    /// have exclusive access). Additionally, the file system should have read access to all files
    /// in the directory it is serving as the FUSE client may send read requests even for files
    /// opened with `O_WRONLY`.
    ///
    /// Therefore callers should only enable this option when they can guarantee that: 1) the file
    /// system has exclusive access to the directory and 2) the file system has read permissions for
    /// all files in that directory.
    ///
    /// The default value for this option is `false`.
    pub writeback: bool,

    /// The path of the root directory.
    ///
    /// The default is `/`.
    pub root_dir: String,

    /// Whether the file system should support Extended Attributes (xattr). Enabling this feature may
    /// have a significant impact on performance, especially on write parallelism. This is the result
    /// of FUSE attempting to remove the special file privileges after each write request.
    ///
    /// The default value for this options is `false`.
    pub xattr: bool,

    /// Optional file descriptor for /proc/self/fd. Callers can obtain a file descriptor and pass it
    /// here, so there's no need to open it in PassthroughFs::new(). This is specially useful for
    /// sandboxing.
    ///
    /// The default is `None`.
    pub proc_sfd_rawfd: Option<RawFd>,

    /// ID of this filesystem to uniquely identify exports. Not supported for macos.
    pub export_fsid: u64,

    /// Table of exported FDs to share with other subsystems. Not supported for macos.
    pub export_table: Option<ExportTable>,

    /// The permission semantics to be emulated. See the documentation for `PermissionSemantics` for
    /// more details.
    pub semantics: PermissionSemantics,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            entry_timeout: Duration::from_secs(5),
            attr_timeout: Duration::from_secs(5),
            cache_policy: Default::default(),
            writeback: false,
            root_dir: String::from("/"),
            xattr: true,
            proc_sfd_rawfd: None,
            export_fsid: 0,
            export_table: None,
            semantics: PermissionSemantics::LinuxComplete,
        }
    }
}

/// A file system that simply "passes through" all requests it receives to the underlying file
/// system. To keep the implementation simple it servers the contents of its root directory. Users
/// that wish to serve only a specific directory should set up the environment so that that
/// directory ends up as the root of the file system process. One way to accomplish this is via a
/// combination of mount namespaces and the pivot_root system call.
pub struct PassthroughFs {
    inodes: RwLock<MultikeyBTreeMap<Inode, InodeAltKey, Arc<InodeData>>>,
    inode_alloc: Arc<InodeAllocator>,

    handles: RwLock<BTreeMap<Handle, Arc<HandleData>>>,
    next_handle: AtomicU64,

    map_windows: Mutex<HashMap<u64, u64>>,

    // Whether writeback caching is enabled for this directory. This will only be true when
    // `cfg.writeback` is true and `init` was called with `FsOptions::WRITEBACK_CACHE`.
    writeback: AtomicBool,
    announce_submounts: AtomicBool,
    cfg: Config,
}

impl PassthroughFs {
    pub fn new(cfg: Config, inode_alloc: Arc<InodeAllocator>) -> io::Result<PassthroughFs> {
        if let PermissionSemantics::Sandbox(config) = cfg.semantics
            && (config.identity.guest_uid == OVERFLOW_ID
                || config.identity.guest_gid == OVERFLOW_ID)
        {
            // The fixed overflow identity must remain distinct from the
            // configured principal or unrelated host owners would alias it.
            return Err(einval());
        }
        let root = CString::new(cfg.root_dir.as_str()).expect("CString::new failed");

        // Safe because this doesn't modify any memory and we check the return value.
        let fd = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                root.as_ptr(),
                libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        unsafe { libc::close(fd) };

        Ok(PassthroughFs {
            inodes: RwLock::new(MultikeyBTreeMap::new()),
            inode_alloc,

            handles: RwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),

            map_windows: Mutex::new(HashMap::new()),

            writeback: AtomicBool::new(false),
            announce_submounts: AtomicBool::new(false),
            cfg,
        })
    }

    fn inode_to_handle(&self, inode: Inode, supports_fd: bool) -> io::Result<InodeHandle> {
        debug!("inode_to_handle: inode={inode}");
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .cloned()
            .ok_or_else(ebadf)?;

        let cstr =
            CString::new(format!("/.vol/{}/{}", data.dev, data.ino)).map_err(|_| einval())?;
        debug!("inode_to_handle: path={}", cstr.to_string_lossy());

        if supports_fd {
            let unlinked_fd = data.unlinked_fd.load(Ordering::Acquire);
            if unlinked_fd >= 0 {
                return Ok(InodeHandle::Fd(unlinked_fd as RawFd));
            }
        }

        Ok(InodeHandle::Path(cstr))
    }

    fn name_to_path(&self, parent: Inode, name: &CStr) -> io::Result<CString> {
        debug!(
            "name_to_path: parent={} name={}",
            parent,
            name.to_string_lossy()
        );
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .cloned()
            .ok_or_else(ebadf)?;

        let cstr = CString::new(format!(
            "/.vol/{}/{}/{}",
            data.dev,
            data.ino,
            name.to_string_lossy()
        ))
        .map_err(|_| einval())?;
        debug!("name_to_path: path={}", cstr.to_string_lossy());
        Ok(cstr)
    }

    fn open_inode(&self, inode: Inode, mut flags: i32) -> io::Result<File> {
        // When writeback caching is enabled, the kernel may send read requests even if the
        // userspace program opened the file write-only. So we need to ensure that we have opened
        // the file for reading as well as writing.
        let writeback = self.writeback.load(Ordering::Relaxed);
        if writeback && flags & libc::O_ACCMODE == libc::O_WRONLY {
            flags &= !libc::O_ACCMODE;
            flags |= libc::O_RDWR;
        }

        // When writeback caching is enabled the kernel is responsible for handling `O_APPEND`.
        // However, this breaks atomicity as the file may have changed on disk, invalidating the
        // cached copy of the data in the kernel and the offset that the kernel thinks is the end of
        // the file. Just allow this for now as it is the user's responsibility to enable writeback
        // caching only for directories that are not shared. It also means that we need to clear the
        // `O_APPEND` flag.
        if writeback && flags & libc::O_APPEND != 0 {
            flags &= !libc::O_APPEND;
        }

        let ihandle = self.inode_to_handle(inode, true)?;
        let fd = match ihandle {
            InodeHandle::Path(c_path) => unsafe {
                libc::open(
                    c_path.as_ptr(),
                    (flags | libc::O_CLOEXEC) & (!libc::O_NOFOLLOW) & (!libc::O_EXLOCK),
                )
            },
            // Check if we have recently unlinked the inode and kept open a file descriptor to it.
            InodeHandle::Fd(fd) => unsafe { libc::dup(fd) },
        };
        if fd < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        // Safe because we just opened this fd.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn do_readdir<F>(
        &self,
        inode: Inode,
        handle: Handle,
        size: u32,
        mut offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        if size == 0 {
            return Ok(());
        }

        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        let mut ds = data.dirstream.lock().unwrap();

        // We use offset == 0 as an indicator of this being either a fresh directory
        // stream or a stream that has been rewound. If that's the case, make sure
        // the cache will be refreshed.
        if offset == 0 && ds.ready {
            let fd = data.file.write().unwrap().as_raw_fd();
            unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
            ds.entries.clear();
            ds.ready = false;
        }

        if !ds.ready {
            // Fill the cache on first call
            if let Err(e) = ds.fill_from_fd(data.file.write().unwrap().as_raw_fd()) {
                if ds.entries.is_empty() {
                    return Err(e);
                }
                // If we got some valid entries before error happened,
                // treat this partial read as success and just log
                // the error.
                warn!("virtio-fs: error in readdir {}: {:?}", inode, e);
            }
            ds.ready = true;
        }

        while let Some(entry) = ds.get_entry(offset) {
            offset += 1;

            let name = entry.name;
            match add_entry(entry) {
                Ok(size) => {
                    if size == 0 {
                        break;
                    }
                }
                Err(e) => {
                    warn!(
                        "virtio-fs: error adding entry {}: {:?}",
                        String::from_utf8_lossy(name),
                        e
                    );
                    break;
                }
            }
        }

        Ok(())
    }

    fn do_open(
        &self,
        ctx: &Context,
        inode: Inode,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        let flags = self.parse_open_flags(flags as i32);
        let sandbox_truncate = (flags & libc::O_TRUNC) != 0
            && matches!(self.cfg.semantics, PermissionSemantics::Sandbox(_));
        let open_flags = if sandbox_truncate {
            flags & !libc::O_TRUNC
        } else {
            flags
        };
        let file = RwLock::new(self.open_inode(inode, open_flags)?);

        if sandbox_truncate && let PermissionSemantics::Sandbox(config) = self.cfg.semantics {
            let fd = file.read().unwrap().as_raw_fd();
            prepare_sandbox_content_mutation(ctx, config, &InodeHandle::Fd(fd), kill_priv)?;
            if unsafe { libc::ftruncate(fd, 0) } < 0 {
                return Err(linux_error(io::Error::last_os_error()));
            }
        }

        // If O_TRUNC and kill_priv (OPEN_KILL_SUIDGID), clear security.capability and suid/sgid
        if (flags & libc::O_TRUNC) != 0
            && kill_priv
            && !matches!(self.cfg.semantics, PermissionSemantics::Sandbox(_))
        {
            let fd = file.read().unwrap().as_raw_fd();
            let ihandle = InodeHandle::Fd(fd);

            remove_security_capability(&ihandle);

            if let Ok(st) = fstat(ctx, self.cfg.semantics, fd, false) {
                let new_mode = clear_suid_sgid(st.st_mode as u32);
                if new_mode != st.st_mode as u32
                    && let Err(err) = set_stat(
                        ctx,
                        self.cfg.semantics,
                        &ihandle,
                        Some(st),
                        None,
                        Some(new_mode),
                    )
                {
                    error!("Couldn't clear suid/sgid for inode {inode}: {err}");
                }
            }
        }

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let data = HandleData {
            inode,
            file,
            dirstream: Mutex::new(DirStream::new()),
        };

        self.handles.write().unwrap().insert(handle, Arc::new(data));

        let mut opts = OpenOptions::empty();
        match self.cfg.cache_policy {
            // We only set the direct I/O option on files.
            CachePolicy::Never => opts.set(OpenOptions::DIRECT_IO, flags & libc::O_DIRECTORY == 0),
            CachePolicy::Always => {
                if flags & libc::O_DIRECTORY == 0 {
                    opts |= OpenOptions::KEEP_CACHE;
                } else {
                    opts |= OpenOptions::CACHE_DIR;
                }
            }
            _ => {}
        };

        Ok((Some(handle), opts))
    }

    fn do_release(&self, inode: Inode, handle: Handle) -> io::Result<()> {
        let mut handles = self.handles.write().unwrap();

        if let btree_map::Entry::Occupied(e) = handles.entry(handle)
            && e.get().inode == inode
        {
            // We don't need to close the file here because that will happen automatically when
            // the last `Arc` is dropped.
            e.remove();
            return Ok(());
        }

        Err(ebadf())
    }

    fn do_getattr(&self, ctx: &Context, inode: Inode) -> io::Result<(bindings::stat64, Duration)> {
        let ihandle = self.inode_to_handle(inode, true)?;
        let st = match ihandle {
            InodeHandle::Path(c_path) => lstat(ctx, self.cfg.semantics, &c_path, false)?,
            InodeHandle::Fd(fd) => fstat(ctx, self.cfg.semantics, fd, false)?,
        };

        Ok((st, self.cfg.attr_timeout))
    }

    fn grab_unlinked_fd(&self, parent_fd: RawFd, name: &CStr) -> io::Result<RawFd> {
        let fd = unsafe {
            libc::openat(
                parent_fd,
                name.as_ptr(),
                libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    fn store_unlinked_fd(&self, ctx: &Context, unlinked_fd: RawFd) -> io::Result<bool> {
        let st = fstat(ctx, self.cfg.semantics, unlinked_fd, true)?;
        let altkey = InodeAltKey {
            ino: st.st_ino,
            dev: st.st_dev,
        };
        // Hold the read lock across the swap: dropping it earlier would let a
        // concurrent `forget` remove this inode (closing its then-`-1`
        // `unlinked_fd`) between our lookup and swap, leaking the fd we store.
        let inodes = self.inodes.read().unwrap();
        if let Some(data) = inodes.get_alt(&altkey) {
            // Swap rather than store so that if this inode already had a
            // preserved fd (e.g. another hard link was unlinked/overwritten
            // earlier), we recover and close it instead of leaking it.
            let old_fd = data.unlinked_fd.swap(unlinked_fd as i64, Ordering::AcqRel);
            if old_fd >= 0 {
                unsafe { libc::close(old_fd as RawFd) };
            }
            // The tracked inode now owns `unlinked_fd` (closed in `forget_one`).
            Ok(true)
        } else {
            // No tracked inode for this (dev, ino): the caller keeps ownership
            // of `unlinked_fd` and must close it to avoid a leak.
            Ok(false)
        }
    }

    fn do_unlink(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        flags: libc::c_int,
    ) -> io::Result<()> {
        let ihandle = self.inode_to_handle(parent, true)?;

        let (fd, close_fd) = match ihandle {
            InodeHandle::Path(c_path) => unsafe {
                (
                    libc::open(c_path.as_ptr(), libc::O_NOFOLLOW | libc::O_CLOEXEC),
                    true,
                )
            },
            InodeHandle::Fd(fd) => (fd, false),
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // After unlinking this inode, we can't keep relying on getting a "/.vol/..." path
        // to operate on it. Before unlinking the inode, grab a file descriptor so we can
        // still operate on it. This one will be closed on "forget_one".
        let unlinked_fd = match self.grab_unlinked_fd(fd, name) {
            Ok(fd) => Some(fd),
            Err(err) => {
                warn!(
                    "Couldn't grab a file descriptor for file \"{}\": {err}",
                    name.to_string_lossy()
                );
                None
            }
        };

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::unlinkat(fd, name.as_ptr(), flags) };
        let err = io::Error::last_os_error();

        if close_fd {
            unsafe { libc::close(fd) };
        }

        if res == 0 {
            if let Some(unlinked_fd) = unlinked_fd {
                match self.store_unlinked_fd(&ctx, unlinked_fd) {
                    // The tracked inode took ownership of the fd.
                    Ok(true) => {}
                    // No tracked inode: we still own the fd and must close it.
                    Ok(false) => unsafe {
                        libc::close(unlinked_fd);
                    },
                    Err(err) => {
                        unsafe { libc::close(unlinked_fd) };
                        warn!("Couldn't store unlinked fd \"{}\": {err}", unlinked_fd);
                    }
                }
            }
            Ok(())
        } else {
            if let Some(unlinked_fd) = unlinked_fd {
                unsafe { libc::close(unlinked_fd) };
            }
            Err(linux_error(err))
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn mknod_complete(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        _rdev: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        let c_path = self.name_to_path(parent, name)?;

        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            Err(linux_error(io::Error::last_os_error()))
        } else {
            let ihandle = InodeHandle::Fd(fd);

            // Set security context
            if let Some(secctx) = extensions.secctx {
                set_secctx(&ihandle, secctx, false)?
            };

            // For mknod, we're forced to store the mode as xattr even in
            // simplified mode, since macOS doesn't allow unprivileged users
            // to create special files (such as sockets or fifos) using mknod.
            if let Err(e) = set_xattr_stat(
                &ctx,
                &ihandle,
                None,
                Some((ctx.uid, ctx.gid)),
                Some(mode & !umask),
            ) {
                unsafe { libc::close(fd) };
                return Err(e);
            }

            unsafe { libc::close(fd) };
            self.lookup(ctx, parent, name)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn mknod_simplified(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        let c_path = self.name_to_path(parent, name)?;

        // macOS doesn't allow us to create UNIX sockets using macOS, so we
        // have to resort to actually creating the socket ourselves and
        // dropping it.
        if (mode as u16 & libc::S_IFMT) == libc::S_IFSOCK {
            let path = c_path.to_str().map_err(|_| einval())?;
            let listener = UnixListener::bind(Path::new(path)).map_err(|_| einval())?;
            // Explicitly drop the listener to make it clear we aren't going
            // to use it. UnixListener's Drop doesn't remove the socket it
            // created, so we can reuse for the guest.
            drop(listener);
        } else {
            let res = unsafe { libc::mknod(c_path.as_ptr(), (mode & !umask) as u16, rdev as i32) };
            if res < 0 {
                return Err(linux_error(io::Error::last_os_error()));
            }
        }

        // Set security context
        if let Some(secctx) = extensions.secctx {
            let ihandle = InodeHandle::Path(c_path.clone());
            set_secctx(&ihandle, secctx, false)?
        };
        self.lookup(ctx, parent, name)
    }

    #[allow(clippy::too_many_arguments)]
    fn mknod_sandbox(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        let kind = mode & libc::S_IFMT as u32;
        if kind != 0 && kind != libc::S_IFREG as u32 {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EOPNOTSUPP)));
        }
        if extensions.secctx.is_some() {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EOPNOTSUPP)));
        }

        let c_path = self.name_to_path(parent, name)?;
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }
        let ihandle = InodeHandle::Fd(fd);
        let guest_mode = libc::S_IFREG as u32 | (mode & !(umask & 0o777));
        if let Err(error) = set_stat(
            &ctx,
            self.cfg.semantics,
            &ihandle,
            None,
            Some((ctx.uid, ctx.gid)),
            Some(guest_mode),
        ) {
            unsafe { libc::close(fd) };
            // A pathname cleanup could delete a host replacement installed
            // after creation. Leave the unadopted entry as a visible host
            // integrity failure instead of risking unrelated data.
            warn!(
                "regular-file metadata attachment failed; a native host entry may remain: {error}"
            );
            return Err(error);
        }
        unsafe { libc::close(fd) };
        self.lookup(ctx, parent, name)
    }

    fn sandbox_inode_metadata(
        &self,
        ctx: &Context,
        mapping: IdentityMapping,
        inode: Inode,
    ) -> io::Result<(InodeHandle, bindings::stat64, Option<GuestMetadata>)> {
        let handle = self.inode_to_handle(inode, true)?;
        let host_st = istat(
            ctx,
            PermissionSemantics::Sandbox(SandboxConfig {
                identity: mapping,
                xattrs_enabled: true,
            }),
            &handle,
            true,
        )?;
        let metadata = read_sandbox_metadata(&handle, host_st)?;
        Ok((handle, host_st, metadata))
    }

    fn sandbox_setxattr(
        &self,
        ctx: &Context,
        mapping: IdentityMapping,
        inode: Inode,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        if name.to_bytes() == &SECURITY_CAPABILITY[..SECURITY_CAPABILITY.len() - 1] {
            if !validate_capability(value) {
                return Err(einval());
            }
            let (handle, host_st, existing) = self.sandbox_inode_metadata(ctx, mapping, inode)?;
            let mut metadata = existing.unwrap_or_else(|| {
                GuestMetadata::from_native(
                    mapping,
                    host_st.st_uid,
                    host_st.st_gid,
                    host_st.st_mode as u32,
                )
            });
            if flags & bindings::LINUX_XATTR_CREATE as u32 != 0 && metadata.capability.is_some() {
                return Err(linux_error(io::Error::from_raw_os_error(libc::EEXIST)));
            }
            if flags & bindings::LINUX_XATTR_REPLACE as u32 != 0 && metadata.capability.is_none() {
                return Err(linux_error(io::Error::from_raw_os_error(libc::ENODATA)));
            }
            metadata.capability = Some(value.to_vec());
            return write_sandbox_metadata(&handle, host_st, &metadata);
        }

        let host_name = user_xattr_host_name(name.to_bytes()).map_err(|error| match error {
            NameError::TooLong => io::Error::from_raw_os_error(LINUX_ERANGE),
            NameError::UnsupportedNamespace => {
                linux_error(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
            }
        })?;
        let host_name = CStr::from_bytes_with_nul(&host_name).map_err(|_| einval())?;
        let mut mac_flags = 0;
        if flags & bindings::LINUX_XATTR_CREATE as u32 != 0 {
            mac_flags |= libc::XATTR_CREATE;
        }
        if flags & bindings::LINUX_XATTR_REPLACE as u32 != 0 {
            mac_flags |= libc::XATTR_REPLACE;
        }
        let (handle, host_st, _) = self.sandbox_inode_metadata(ctx, mapping, inode)?;
        let options = sandbox_xattr_options(host_st);
        let result = match handle {
            InodeHandle::Path(path) => unsafe {
                libc::setxattr(
                    path.as_ptr(),
                    host_name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                    mac_flags | options,
                )
            },
            InodeHandle::Fd(fd) => unsafe {
                libc::fsetxattr(
                    fd,
                    host_name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                    mac_flags | options,
                )
            },
        };
        if result == 0 {
            Ok(())
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn sandbox_getxattr(
        &self,
        ctx: &Context,
        mapping: IdentityMapping,
        inode: Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        if name.to_bytes() == &SECURITY_CAPABILITY[..SECURITY_CAPABILITY.len() - 1] {
            let (_, _, metadata) = self.sandbox_inode_metadata(ctx, mapping, inode)?;
            let capability = metadata
                .and_then(|metadata| metadata.capability)
                .ok_or_else(|| linux_error(io::Error::from_raw_os_error(libc::ENODATA)))?;
            if size == 0 {
                return Ok(GetxattrReply::Count(capability.len() as u32));
            }
            if capability.len() > size as usize {
                return Err(io::Error::from_raw_os_error(LINUX_ERANGE));
            }
            return Ok(GetxattrReply::Value(capability));
        }

        let host_name = user_xattr_host_name(name.to_bytes()).map_err(|error| match error {
            NameError::TooLong => io::Error::from_raw_os_error(LINUX_ERANGE),
            NameError::UnsupportedNamespace => {
                linux_error(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
            }
        })?;
        let host_name = CStr::from_bytes_with_nul(&host_name).map_err(|_| einval())?;
        let (handle, host_st, _) = self.sandbox_inode_metadata(ctx, mapping, inode)?;
        let options = sandbox_xattr_options(host_st);
        let mut value = vec![0; size as usize];
        let result = match handle {
            InodeHandle::Path(path) => unsafe {
                libc::getxattr(
                    path.as_ptr(),
                    host_name.as_ptr(),
                    if size == 0 {
                        null_mut()
                    } else {
                        value.as_mut_ptr().cast()
                    },
                    value.len(),
                    0,
                    options,
                )
            },
            InodeHandle::Fd(fd) => unsafe {
                libc::fgetxattr(
                    fd,
                    host_name.as_ptr(),
                    if size == 0 {
                        null_mut()
                    } else {
                        value.as_mut_ptr().cast()
                    },
                    value.len(),
                    0,
                    options,
                )
            },
        };
        if result < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }
        if size == 0 {
            Ok(GetxattrReply::Count(result as u32))
        } else {
            value.truncate(result as usize);
            Ok(GetxattrReply::Value(value))
        }
    }

    fn sandbox_listxattr(
        &self,
        ctx: &Context,
        mapping: IdentityMapping,
        inode: Inode,
        size: u32,
    ) -> io::Result<ListxattrReply> {
        let (handle, host_st, metadata) = self.sandbox_inode_metadata(ctx, mapping, inode)?;
        let options = sandbox_xattr_options(host_st);
        let raw = loop {
            let count = match &handle {
                InodeHandle::Path(path) => unsafe {
                    libc::listxattr(path.as_ptr(), null_mut(), 0, options)
                },
                InodeHandle::Fd(fd) => unsafe { libc::flistxattr(*fd, null_mut(), 0, options) },
            };
            if count < 0 {
                return Err(linux_error(io::Error::last_os_error()));
            }
            let mut raw = vec![0; count as usize];
            let read = match &handle {
                InodeHandle::Path(path) => unsafe {
                    libc::listxattr(path.as_ptr(), raw.as_mut_ptr().cast(), raw.len(), options)
                },
                InodeHandle::Fd(fd) => unsafe {
                    libc::flistxattr(*fd, raw.as_mut_ptr().cast(), raw.len(), options)
                },
            };
            if read < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ERANGE) {
                    continue;
                }
                return Err(linux_error(error));
            }
            raw.truncate(read as usize);
            break raw;
        };

        let mut names = Vec::new();
        for host_name in raw.split(|byte| *byte == 0) {
            let Some(guest_name) = guest_name_from_carrier(host_name) else {
                continue;
            };
            if !guest_name.starts_with(b"user.") {
                continue;
            }
            names.extend_from_slice(guest_name);
            names.push(0);
        }
        if metadata.and_then(|metadata| metadata.capability).is_some() {
            names.extend_from_slice(SECURITY_CAPABILITY);
        }
        if size == 0 {
            return Ok(ListxattrReply::Count(names.len() as u32));
        }
        if names.len() > size as usize {
            return Err(io::Error::from_raw_os_error(LINUX_ERANGE));
        }
        Ok(ListxattrReply::Names(names))
    }

    fn sandbox_removexattr(
        &self,
        ctx: &Context,
        mapping: IdentityMapping,
        inode: Inode,
        name: &CStr,
    ) -> io::Result<()> {
        if name.to_bytes() == &SECURITY_CAPABILITY[..SECURITY_CAPABILITY.len() - 1] {
            let (handle, host_st, metadata) = self.sandbox_inode_metadata(ctx, mapping, inode)?;
            let mut metadata = metadata
                .filter(|metadata| metadata.capability.is_some())
                .ok_or_else(|| linux_error(io::Error::from_raw_os_error(libc::ENODATA)))?;
            metadata.capability = None;
            return write_sandbox_metadata(&handle, host_st, &metadata);
        }

        let host_name = user_xattr_host_name(name.to_bytes()).map_err(|error| match error {
            NameError::TooLong => io::Error::from_raw_os_error(LINUX_ERANGE),
            NameError::UnsupportedNamespace => {
                linux_error(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
            }
        })?;
        let host_name = CStr::from_bytes_with_nul(&host_name).map_err(|_| einval())?;
        let (handle, host_st, _) = self.sandbox_inode_metadata(ctx, mapping, inode)?;
        let options = sandbox_xattr_options(host_st);
        let result = match handle {
            InodeHandle::Path(path) => unsafe {
                libc::removexattr(path.as_ptr(), host_name.as_ptr(), options)
            },
            InodeHandle::Fd(fd) => unsafe { libc::fremovexattr(fd, host_name.as_ptr(), options) },
        };
        if result == 0 {
            Ok(())
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn entry_from_stat(&self, parent: Inode, st: bindings::stat64) -> io::Result<Entry> {
        let parent_data = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .cloned()
            .ok_or_else(ebadf)?;

        let mut attr_flags: u32 = 0;

        if st.st_mode & libc::S_IFMT == libc::S_IFDIR
            && self.announce_submounts.load(Ordering::Relaxed)
            && (st.st_dev != parent_data.dev)
        {
            attr_flags |= fuse::ATTR_SUBMOUNT;
        }

        let altkey = InodeAltKey {
            ino: st.st_ino,
            dev: st.st_dev,
        };
        let data = self.inodes.read().unwrap().get_alt(&altkey).cloned();

        let inode = if let Some(data) = data {
            // Matches with the release store in `forget`.
            data.refcount.fetch_add(1, Ordering::Acquire);
            data.inode
        } else {
            // There is a possible race here where 2 threads end up adding the same file
            // into the inode list.  However, since each of those will get a unique Inode
            // value and unique file descriptors this shouldn't be that much of a problem.
            let inode = self.inode_alloc.next();
            self.inodes.write().unwrap().insert(
                inode,
                InodeAltKey {
                    ino: st.st_ino,
                    dev: st.st_dev,
                },
                Arc::new(InodeData {
                    inode,
                    ino: st.st_ino,
                    dev: st.st_dev,
                    refcount: AtomicU64::new(1),
                    unlinked_fd: AtomicI64::new(-1),
                }),
            );

            inode
        };

        Ok(Entry {
            inode,
            generation: 0,
            attr: st,
            attr_flags,
            attr_timeout: self.cfg.attr_timeout,
            entry_timeout: self.cfg.entry_timeout,
        })
    }

    fn entry_from_file(&self, ctx: &Context, parent: Inode, file: &File) -> io::Result<Entry> {
        let st = fstat(ctx, self.cfg.semantics, file.as_raw_fd(), false)?;
        self.entry_from_stat(parent, st)
    }

    fn parse_open_flags(&self, flags: i32) -> i32 {
        let mut mflags: i32 = flags & 0b11;

        if (flags & bindings::LINUX_O_NONBLOCK) != 0 {
            mflags |= libc::O_NONBLOCK;
        }
        if (flags & bindings::LINUX_O_APPEND) != 0 {
            mflags |= libc::O_APPEND;
        }
        if (flags & bindings::LINUX_O_CREAT) != 0 {
            mflags |= libc::O_CREAT;
        }
        if (flags & bindings::LINUX_O_TRUNC) != 0 {
            mflags |= libc::O_TRUNC;
        }
        if (flags & bindings::LINUX_O_EXCL) != 0 {
            mflags |= libc::O_EXCL;
        }
        if (flags & bindings::LINUX_O_NOFOLLOW) != 0 {
            mflags |= libc::O_NOFOLLOW;
        }
        if (flags & bindings::LINUX_O_CLOEXEC) != 0 {
            mflags |= libc::O_CLOEXEC;
        }

        mflags
    }
}

fn do_set_secctx(file: &InodeHandle, secctx: &SecContext, options: i32) -> io::Result<()> {
    let ret = match file {
        InodeHandle::Path(path) => unsafe {
            libc::setxattr(
                path.as_ptr(),
                secctx.name.as_ptr(),
                secctx.secctx.as_ptr() as *const libc::c_void,
                secctx.secctx.len(),
                0,
                options,
            )
        },
        InodeHandle::Fd(fd) => unsafe {
            libc::fsetxattr(
                *fd,
                secctx.name.as_ptr(),
                secctx.secctx.as_ptr() as *const libc::c_void,
                secctx.secctx.len(),
                0,
                options,
            )
        },
    };

    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_secctx(file: &InodeHandle, secctx: SecContext, symlink: bool) -> io::Result<()> {
    let options = if symlink { libc::XATTR_NOFOLLOW } else { 0 };

    match do_set_secctx(file, &secctx, options) {
        Ok(()) => return Ok(()),
        Err(err) => {
            let err_os = err.raw_os_error();
            if err_os != Some(libc::EACCES) && err_os != Some(libc::EPERM) {
                return Err(linux_error(err));
            }
        }
    }

    // The file mode doesn't allow setting xattrs. Temporarily grant the owner
    // write permission, set the attribute, then restore the original mode.
    let mut st = MaybeUninit::<bindings::stat64>::zeroed();
    let ret = match file {
        InodeHandle::Path(path) => unsafe { libc::lstat(path.as_ptr(), st.as_mut_ptr()) },
        InodeHandle::Fd(fd) => unsafe { libc::fstat(*fd, st.as_mut_ptr()) },
    };
    if ret < 0 {
        return Err(linux_error(io::Error::last_os_error()));
    }
    let st = unsafe { st.assume_init() };

    let tmp_mode = st.st_mode | libc::S_IWUSR;
    let ret = match file {
        InodeHandle::Path(path) => unsafe { libc::chmod(path.as_ptr(), tmp_mode) },
        InodeHandle::Fd(fd) => unsafe { libc::fchmod(*fd, tmp_mode) },
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        error!("set_secctx: chmod failed: {}", err);
        return Err(linux_error(err));
    }

    let secctx_ret = do_set_secctx(file, &secctx, options);

    let ret = match file {
        InodeHandle::Path(path) => unsafe { libc::chmod(path.as_ptr(), st.st_mode) },
        InodeHandle::Fd(fd) => unsafe { libc::fchmod(*fd, st.st_mode) },
    };
    if ret < 0 {
        error!(
            "set_secctx: chmod restore failed: {}",
            io::Error::last_os_error()
        );
    }

    match secctx_ret {
        Ok(()) => Ok(()),
        Err(err) => Err(linux_error(err)),
    }
}

/// Remove the security.capability extended attribute
fn remove_security_capability(file: &InodeHandle) {
    let ret = match file {
        InodeHandle::Path(path) => unsafe {
            libc::removexattr(path.as_ptr(), SECURITY_CAPABILITY.as_ptr() as *const i8, 0)
        },
        InodeHandle::Fd(fd) => unsafe {
            libc::fremovexattr(*fd, SECURITY_CAPABILITY.as_ptr() as *const i8, 0)
        },
    };

    // ENODATA means the attribute didn't exist, which is fine
    if ret != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ENODATA) {
        warn!("Error removing security.capability from file");
    }
}

/// Clear suid/sgid bits from mode.
/// sgid is cleared only if group executable bit is set.
fn clear_suid_sgid(mode: u32) -> u32 {
    let mut new_mode = mode;

    // Clear suid bit
    new_mode &= !libc::S_ISUID as u32;

    // Clear sgid bit only if group executable bit is set
    if (mode & libc::S_IXGRP as u32) != 0 {
        new_mode &= !libc::S_ISGID as u32;
    }

    new_mode
}

fn forget_one(
    inodes: &mut MultikeyBTreeMap<Inode, InodeAltKey, Arc<InodeData>>,
    inode: Inode,
    count: u64,
) {
    if let Some(data) = inodes.get(&inode) {
        // Acquiring the write lock on the inode map prevents new lookups from incrementing the
        // refcount but there is the possibility that a previous lookup already acquired a
        // reference to the inode data and is in the process of updating the refcount so we need
        // to loop here until we can decrement successfully.
        loop {
            let refcount = data.refcount.load(Ordering::Relaxed);

            // Saturating sub because it doesn't make sense for a refcount to go below zero and
            // we don't want misbehaving clients to cause integer overflow.
            let new_count = refcount.saturating_sub(count);

            // Synchronizes with the acquire load in `lookup`.
            if data
                .refcount
                .compare_exchange(refcount, new_count, Ordering::Release, Ordering::Relaxed)
                .unwrap()
                == refcount
            {
                if new_count == 0 {
                    // If we have unlinked this inode, we have opened a file descriptor to be
                    // able to operate on it without a path. Close it now.
                    let fd = data.unlinked_fd.load(Ordering::Acquire);
                    if fd >= 0 {
                        unsafe { libc::close(fd as RawFd) };
                    }
                    // We just removed the last refcount for this inode. There's no need for an
                    // acquire fence here because we hold a write lock on the inode map and any
                    // thread that is waiting to do a forget on the same inode will have to wait
                    // until we release the lock. So there's is no other release store for us to
                    // synchronize with before deleting the entry.
                    inodes.remove(&inode);
                }
                break;
            }
        }
    }
}

impl FileSystem for PassthroughFs {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        let root = CString::new(self.cfg.root_dir.as_str()).expect("CString::new failed");

        // Safe because this doesn't modify any memory and we check the return value.
        // We use `O_PATH` because we just want this for traversing the directory tree
        // and not for actually reading the contents.
        let fd = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                root.as_ptr(),
                libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because we just opened this fd above.
        let f = unsafe { File::from_raw_fd(fd) };

        // Build a fake Context for fstat, it won't be using it anyways
        // as it'll be only looking at the host's bits.
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let st = fstat(&ctx, self.cfg.semantics, f.as_raw_fd(), true)?;

        // Safe because this doesn't modify any memory and there is no need to check the return
        // value because this system call always succeeds. We need to clear the umask here because
        // we want the client to be able to set all the bits in the mode.
        unsafe { libc::umask(0o000) };

        let mut inodes = self.inodes.write().unwrap();

        // Not sure why the root inode gets a refcount of 2 but that's what libfuse does.
        inodes.insert(
            fuse::ROOT_ID,
            InodeAltKey {
                ino: st.st_ino,
                dev: st.st_dev,
            },
            Arc::new(InodeData {
                inode: fuse::ROOT_ID,
                ino: st.st_ino,
                dev: st.st_dev,
                refcount: AtomicU64::new(2),
                unlinked_fd: AtomicI64::new(-1),
            }),
        );

        let mut opts = FsOptions::empty();
        if self.cfg.writeback && capable.contains(FsOptions::WRITEBACK_CACHE) {
            opts |= FsOptions::WRITEBACK_CACHE;
            self.writeback.store(true, Ordering::Relaxed);
        }

        if capable.contains(FsOptions::SUBMOUNTS) {
            opts |= FsOptions::SUBMOUNTS;
            self.announce_submounts.store(true, Ordering::Relaxed);
        }

        // Sandbox cannot apply Linux security labels faithfully, so it must
        // not negotiate per-create security contexts. Other macOS passthrough
        // modes retain the existing carrier-xattr implementation.
        if !matches!(self.cfg.semantics, PermissionSemantics::Sandbox(_))
            && capable.contains(FsOptions::SECURITY_CTX)
        {
            opts |= FsOptions::SECURITY_CTX;
        }

        if matches!(self.cfg.semantics, PermissionSemantics::Sandbox(_))
            && capable.contains(FsOptions::HANDLE_KILLPRIV_V2)
        {
            opts |= FsOptions::HANDLE_KILLPRIV_V2;
        }

        Ok(opts)
    }

    fn destroy(&self) {
        self.handles.write().unwrap().clear();
        self.inodes.write().unwrap().clear();
    }

    fn statfs(&self, _ctx: Context, inode: Inode) -> io::Result<bindings::statvfs64> {
        let mut out = MaybeUninit::<bindings::statvfs64>::zeroed();

        let res = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => unsafe {
                bindings::statvfs64(c_path.as_ptr(), out.as_mut_ptr())
            },
            InodeHandle::Fd(fd) => unsafe { bindings::fstatvfs64(fd, out.as_mut_ptr()) },
        };
        if res == 0 {
            // Safe because the kernel guarantees that `out` has been initialized.
            Ok(unsafe { out.assume_init() })
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn lookup(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        let c_path = self.name_to_path(parent, name)?;
        let st = lstat(&ctx, self.cfg.semantics, &c_path, false)?;

        debug!(
            "lookup: inode={} path={}",
            st.st_ino,
            c_path.to_str().unwrap()
        );

        self.entry_from_stat(parent, st)
    }

    fn forget(&self, _ctx: Context, inode: Inode, count: u64) {
        let mut inodes = self.inodes.write().unwrap();

        forget_one(&mut inodes, inode, count)
    }

    fn batch_forget(&self, _ctx: Context, requests: Vec<(Inode, u64)>) {
        let mut inodes = self.inodes.write().unwrap();

        for (inode, count) in requests {
            forget_one(&mut inodes, inode, count)
        }
    }

    fn opendir(
        &self,
        ctx: Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.do_open(&ctx, inode, false, flags | libc::O_DIRECTORY as u32)
    }

    fn releasedir(
        &self,
        _ctx: Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
    ) -> io::Result<()> {
        self.do_release(inode, handle)
    }

    fn mkdir(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        if matches!(self.cfg.semantics, PermissionSemantics::Sandbox(_))
            && extensions.secctx.is_some()
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EOPNOTSUPP)));
        }
        let c_path = self.name_to_path(parent, name)?;

        let (host_mode, complete) = match self.cfg.semantics {
            PermissionSemantics::LinuxComplete => (0o700, true),
            PermissionSemantics::LinuxSimplified => ((mode & !umask) as u16, false),
            PermissionSemantics::Sandbox(_) => (0o700, true),
        };

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::mkdir(c_path.as_ptr(), host_mode) };
        if res == 0 {
            let ihandle = InodeHandle::Path(c_path.clone());
            // Set security context
            if let Some(secctx) = extensions.secctx {
                set_secctx(&ihandle, secctx, false)?
            };

            if complete
                && let Err(error) = set_stat(
                    &ctx,
                    self.cfg.semantics,
                    &ihandle,
                    None,
                    Some((ctx.uid, ctx.gid)),
                    Some(mode & !umask),
                )
            {
                if matches!(self.cfg.semantics, PermissionSemantics::Sandbox(_)) {
                    // A pathname cleanup could delete a host replacement
                    // installed after mkdir. The failed operation may leave a
                    // native entry, matching the documented host boundary.
                    warn!(
                        "directory metadata attachment failed; a native host entry may remain: {error}"
                    );
                }
                return Err(error);
            }
            self.lookup(ctx, parent, name)
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn rmdir(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.do_unlink(ctx, parent, name, libc::AT_REMOVEDIR)
    }

    fn readdir<F>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        self.do_readdir(inode, handle, size, offset, add_entry)
    }

    fn readdirplus<F>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry, Entry) -> io::Result<usize>,
    {
        self.do_readdir(inode, handle, size, offset, |dir_entry| {
            // Safe because the kernel guarantees that the buffer is nul-terminated. Additionally,
            // the kernel will pad the name with '\0' bytes up to 8-byte alignment and there's no
            // way for us to know exactly how many padding bytes there are. This would cause
            // `CStr::from_bytes_with_nul` to return an error because it would think there are
            // interior '\0' bytes. We trust the kernel to provide us with properly formatted data
            // so we'll just skip the checks here.
            let name = unsafe { CStr::from_bytes_with_nul_unchecked(dir_entry.name) };
            let entry = self.lookup(ctx, inode, name)?;

            add_entry(dir_entry, entry)
        })
    }

    fn open(
        &self,
        ctx: Context,
        inode: Inode,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.do_open(&ctx, inode, kill_priv, flags)
    }

    fn release(
        &self,
        _ctx: Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        self.do_release(inode, handle)
    }

    fn create(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        kill_priv: bool,
        flags: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<(Entry, Option<Handle>, OpenOptions)> {
        if matches!(self.cfg.semantics, PermissionSemantics::Sandbox(_))
            && extensions.secctx.is_some()
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EOPNOTSUPP)));
        }
        let c_path = self.name_to_path(parent, name)?;

        let flags = self.parse_open_flags(flags as i32);
        let sandbox = matches!(self.cfg.semantics, PermissionSemantics::Sandbox(_));
        let sandbox_truncate = sandbox && flags & libc::O_TRUNC != 0;
        let open_flags = if sandbox_truncate {
            flags & !libc::O_TRUNC
        } else {
            flags
        };
        let (host_mode, complete) = match self.cfg.semantics {
            PermissionSemantics::LinuxComplete => {
                let mode = if (flags & libc::O_DIRECTORY) != 0 {
                    0o700
                } else {
                    0o600
                };
                (mode, true)
            }
            PermissionSemantics::LinuxSimplified => (mode & !(umask & 0o777), false),
            PermissionSemantics::Sandbox(_) => {
                let mode = if (flags & libc::O_DIRECTORY) != 0 {
                    0o700
                } else {
                    0o600
                };
                (mode, true)
            }
        };

        // Safe because this doesn't modify any memory and we check the return value. We don't
        // really check `flags` because if the kernel can't handle poorly specified flags then we
        // have much bigger problems.
        let (fd, created) = if sandbox {
            open_sandbox_create(&c_path, open_flags, host_mode)?
        } else {
            let fd = unsafe {
                libc::open(
                    c_path.as_ptr(),
                    open_flags | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    host_mode,
                )
            };
            if fd < 0 {
                return Err(linux_error(io::Error::last_os_error()));
            }
            (fd, true)
        };
        // Safe because this function now owns the descriptor returned above.
        // Keeping it in File ensures every later error path closes it.
        let file = unsafe { File::from_raw_fd(fd) };
        let ihandle = InodeHandle::Fd(file.as_raw_fd());
        let guest_mode = libc::S_IFREG as u32 | (mode & !(umask & 0o777));
        let guest_mode = if sandbox_truncate && kill_priv {
            clear_suid_sgid(guest_mode)
        } else {
            guest_mode
        };

        if complete
            && (!sandbox || created)
            && let Err(e) = set_stat(
                &ctx,
                self.cfg.semantics,
                &ihandle,
                None,
                Some((ctx.uid, ctx.gid)),
                Some(guest_mode),
            )
        {
            if sandbox && created {
                // Even though this request created the inode behind `fd`, the
                // pathname may now name a host replacement. Never unlink by
                // path after the metadata operation has failed.
                warn!("file metadata attachment failed; a native host entry may remain: {e}");
            }
            return Err(e);
        }

        // Set security context
        if let Some(secctx) = extensions.secctx {
            set_secctx(&ihandle, secctx, false)?
        };

        if sandbox_truncate
            && !created
            && let PermissionSemantics::Sandbox(config) = self.cfg.semantics
        {
            // As in OPEN, remove privilege metadata before mutating existing
            // contents. A newly created file is already empty, and its mode
            // was adjusted above when kill_priv required it.
            prepare_sandbox_content_mutation(&ctx, config, &ihandle, kill_priv)?;
            if unsafe { libc::ftruncate(fd, 0) } < 0 {
                let error = linux_error(io::Error::last_os_error());
                return Err(error);
            }
        } else if (flags & libc::O_TRUNC) != 0 && kill_priv && !sandbox {
            // LinuxComplete stores capabilities separately and has already
            // updated the new file's ownership and mode above.
            remove_security_capability(&ihandle);
        }

        // Build the entry from the opened descriptor. Looking the pathname up
        // again could bind the entry to a host replacement while the returned
        // handle still refers to the file opened above.
        let entry = self.entry_from_file(&ctx, parent, &file)?;
        let file = RwLock::new(file);

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let data = HandleData {
            inode: entry.inode,
            file,
            dirstream: Mutex::new(DirStream::new()),
        };

        self.handles.write().unwrap().insert(handle, Arc::new(data));

        let mut opts = OpenOptions::empty();
        match self.cfg.cache_policy {
            CachePolicy::Never => opts |= OpenOptions::DIRECT_IO,
            CachePolicy::Always => opts |= OpenOptions::KEEP_CACHE,
            _ => {}
        };

        Ok((entry, Some(handle), opts))
    }

    fn unlink(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.do_unlink(ctx, parent, name, 0)
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mut w: W,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        debug!("read: {inode:?}");
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        // This is safe because write_from uses preadv64, so the underlying file descriptor
        // offset is not affected by this operation.
        let f = data.file.read().unwrap();
        w.write_from(&f, size as usize, offset)
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        mut r: R,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        kill_priv: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        // This is safe because read_to uses pwritev64, so the underlying file descriptor
        // offset is not affected by this operation.
        let f = data.file.read().unwrap();
        if let PermissionSemantics::Sandbox(config) = self.cfg.semantics {
            // Capability metadata is removed before every content write;
            // kill_priv controls the setuid/setgid bits only. If replacement
            // fails, the write must not happen; if the later write fails,
            // keeping privileges removed is the conservative result.
            prepare_sandbox_content_mutation(
                &ctx,
                config,
                &InodeHandle::Fd(f.as_raw_fd()),
                kill_priv,
            )?;
        }
        let result = r.read_to(&f, size as usize, offset);

        // If write succeeded and kill_priv is set, clear security.capability and suid/sgid
        if result.is_ok()
            && kill_priv
            && !matches!(self.cfg.semantics, PermissionSemantics::Sandbox(_))
        {
            let fd = f.as_raw_fd();
            let ihandle = InodeHandle::Fd(fd);

            remove_security_capability(&ihandle);

            if let Ok(st) = fstat(&ctx, self.cfg.semantics, fd, false) {
                let new_mode = clear_suid_sgid(st.st_mode as u32);
                if new_mode != st.st_mode as u32 {
                    // Update mode in xattr
                    if let Err(err) = set_stat(
                        &ctx,
                        self.cfg.semantics,
                        &ihandle,
                        Some(st),
                        None,
                        Some(new_mode),
                    ) {
                        error!("Couldn't clear suid/sgid for inode {inode}: {err}");
                    }
                }
            }
        }

        result
    }

    fn getattr(
        &self,
        ctx: Context,
        inode: Inode,
        _handle: Option<Handle>,
    ) -> io::Result<(bindings::stat64, Duration)> {
        self.do_getattr(&ctx, inode)
    }

    fn setattr(
        &self,
        ctx: Context,
        inode: Inode,
        attr: bindings::stat64,
        handle: Option<Handle>,
        valid: SetattrValid,
    ) -> io::Result<(bindings::stat64, Duration)> {
        // If we have a handle then use it otherwise get a new fd from the inode.
        let ihandle = if let Some(handle) = handle {
            let hd = self
                .handles
                .read()
                .unwrap()
                .get(&handle)
                .filter(|hd| hd.inode == inode)
                .cloned()
                .ok_or_else(ebadf)?;

            let fd = hd.file.write().unwrap().as_raw_fd();
            InodeHandle::Fd(fd)
        } else {
            self.inode_to_handle(inode, true)?
        };

        if let PermissionSemantics::Sandbox(config) = self.cfg.semantics {
            let metadata_mode = valid
                .contains(SetattrValid::MODE)
                .then_some(attr.st_mode as u32);
            let metadata_owner = valid
                .intersects(SetattrValid::UID | SetattrValid::GID)
                .then_some((
                    if valid.contains(SetattrValid::UID) {
                        attr.st_uid
                    } else {
                        u32::MAX
                    },
                    if valid.contains(SetattrValid::GID) {
                        attr.st_gid
                    } else {
                        u32::MAX
                    },
                ));
            let clear_capability = metadata_owner.is_some() || valid.contains(SetattrValid::SIZE);
            let clear_mode_privileges = metadata_owner.is_some()
                || (valid.contains(SetattrValid::SIZE)
                    && valid.contains(SetattrValid::KILL_SUIDGID));
            if metadata_mode.is_some()
                || metadata_owner.is_some()
                || clear_capability
                || clear_mode_privileges
            {
                // The complete record is replaced once so one setattr request
                // can never publish a new owner with stale privilege bits.
                update_sandbox_metadata(
                    &ctx,
                    config,
                    &ihandle,
                    None,
                    metadata_owner,
                    metadata_mode,
                    clear_capability,
                    clear_mode_privileges,
                    metadata_mode.is_some() || metadata_owner.is_some(),
                )?;
            }
        }

        if valid.contains(SetattrValid::MODE)
            && !matches!(self.cfg.semantics, PermissionSemantics::Sandbox(_))
        {
            set_stat(
                &ctx,
                self.cfg.semantics,
                &ihandle,
                None,
                None,
                Some(attr.st_mode as u32),
            )?
        }

        if valid.intersects(SetattrValid::UID | SetattrValid::GID)
            && !matches!(self.cfg.semantics, PermissionSemantics::Sandbox(_))
        {
            let uid = if valid.contains(SetattrValid::UID) {
                attr.st_uid
            } else {
                // Cannot use -1 here because these are unsigned values.
                u32::MAX
            };
            let gid = if valid.contains(SetattrValid::GID) {
                attr.st_gid
            } else {
                // Cannot use -1 here because these are unsigned values.
                u32::MAX
            };

            remove_security_capability(&ihandle);
            let st = istat(&ctx, self.cfg.semantics, &ihandle, false)?;

            // Clear suid/sgid if UID or GID is being changed
            let new_mode = clear_suid_sgid(st.st_mode as u32);
            let new_mode = if new_mode != st.st_mode as u32 {
                Some(new_mode)
            } else {
                None
            };
            set_stat(
                &ctx,
                self.cfg.semantics,
                &ihandle,
                Some(st),
                Some((uid, gid)),
                new_mode,
            )?;
        }

        if valid.contains(SetattrValid::SIZE) {
            // Safe because this doesn't modify any memory and we check the return value.
            match ihandle {
                InodeHandle::Fd(fd) => {
                    let res = unsafe { libc::ftruncate(fd, attr.st_size) };
                    if res < 0 {
                        return Err(linux_error(io::Error::last_os_error()));
                    }

                    if !matches!(self.cfg.semantics, PermissionSemantics::Sandbox(_)) {
                        // Clear security.capability on truncate unconditionally
                        remove_security_capability(&ihandle);
                        let st = fstat(&ctx, self.cfg.semantics, fd, false)?;
                        let new_mode = clear_suid_sgid(st.st_mode as u32);
                        if new_mode != st.st_mode as u32 {
                            set_stat(
                                &ctx,
                                self.cfg.semantics,
                                &ihandle,
                                Some(st),
                                None,
                                Some(new_mode),
                            )?;
                        }
                    }
                }
                InodeHandle::Path(_) => {
                    // There is no `ftruncateat` so we need to get a new fd and truncate it.
                    let f = self.open_inode(inode, libc::O_NONBLOCK | libc::O_RDWR)?;
                    let res = unsafe { libc::ftruncate(f.as_raw_fd(), attr.st_size) };
                    if res < 0 {
                        return Err(linux_error(io::Error::last_os_error()));
                    }

                    if !matches!(self.cfg.semantics, PermissionSemantics::Sandbox(_)) {
                        // Clear security.capability on truncate unconditionally
                        //
                        // Do this here even if it means duplicating the code above to be able to
                        // reuse the FD we just opened, thus reducing the number of syscalls.
                        let ihandle = InodeHandle::Fd(f.as_raw_fd());
                        remove_security_capability(&ihandle);
                        let st = istat(&ctx, self.cfg.semantics, &ihandle, false)?;
                        let new_mode = clear_suid_sgid(st.st_mode as u32);
                        if new_mode != st.st_mode as u32 {
                            set_stat(
                                &ctx,
                                self.cfg.semantics,
                                &ihandle,
                                Some(st),
                                None,
                                Some(new_mode),
                            )?;
                        }
                    }
                }
            };
        }

        if valid.intersects(SetattrValid::ATIME | SetattrValid::MTIME) {
            let mut tvs = [
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
            ];

            if valid.contains(SetattrValid::ATIME_NOW) {
                tvs[0].tv_nsec = libc::UTIME_NOW;
            } else if valid.contains(SetattrValid::ATIME) {
                tvs[0].tv_sec = attr.st_atime;
                tvs[0].tv_nsec = attr.st_atime_nsec;
            }

            if valid.contains(SetattrValid::MTIME_NOW) {
                tvs[1].tv_nsec = libc::UTIME_NOW;
            } else if valid.contains(SetattrValid::MTIME) {
                tvs[1].tv_sec = attr.st_mtime;
                tvs[1].tv_nsec = attr.st_mtime_nsec;
            }

            // Safe because this doesn't modify any memory and we check the return value.
            let res = match ihandle {
                InodeHandle::Fd(fd) => unsafe { libc::futimens(fd, tvs.as_ptr()) },
                InodeHandle::Path(c_path) => unsafe {
                    let fd = libc::open(c_path.as_ptr(), libc::O_SYMLINK | libc::O_CLOEXEC);
                    let res = libc::futimens(fd, tvs.as_ptr());
                    libc::close(fd);
                    res
                },
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        self.do_getattr(&ctx, inode)
    }

    fn rename(
        &self,
        ctx: Context,
        olddir: Inode,
        oldname: &CStr,
        newdir: Inode,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        let mut mflags: u32 = 0;
        if ((flags as i32) & bindings::LINUX_RENAME_NOREPLACE) != 0 {
            mflags |= libc::RENAME_EXCL;
        }
        if ((flags as i32) & bindings::LINUX_RENAME_EXCHANGE) != 0 {
            mflags |= libc::RENAME_SWAP;
        }

        if ((flags as i32) & bindings::LINUX_RENAME_WHITEOUT) != 0
            && ((flags as i32) & bindings::LINUX_RENAME_EXCHANGE) != 0
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EINVAL)));
        }
        if ((flags as i32) & bindings::LINUX_RENAME_WHITEOUT) != 0
            && matches!(self.cfg.semantics, PermissionSemantics::Sandbox(_))
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EOPNOTSUPP)));
        }

        let old_cpath = self.name_to_path(olddir, oldname)?;
        let new_cpath = self.name_to_path(newdir, newname)?;

        // macOS addresses inodes by their volfs path ("/.vol/{dev}/{ino}"),
        // which only resolves while the inode still has a directory entry. A
        // rename that REPLACES an existing target drops that target's last
        // link, so any inode the guest still holds open there would afterwards
        // resolve to a dangling volfs path and fail path-based ops
        // (getattr/open/setattr/...) with ENOENT (e.g. apt/dpkg's atomic
        // rewrite of /var/lib/dpkg/status, surfaced as
        // "close (2: No such file or directory)"). `do_unlink` already guards
        // the unlink case by stashing an fd to the doomed inode in
        // `InodeData.unlinked_fd`; mirror that for the overwritten target. Grab
        // it *before* the rename, while its entry still exists. RENAME_SWAP
        // keeps both inodes linked and RENAME_EXCL never overwrites, so skip
        // those; best-effort otherwise (a non-overwriting rename finds nothing).
        let doomed_fd = if (flags as i32)
            & (bindings::LINUX_RENAME_EXCHANGE | bindings::LINUX_RENAME_NOREPLACE)
            == 0
        {
            match self.inode_to_handle(newdir, true) {
                Ok(InodeHandle::Path(newdir_cpath)) => {
                    let newdir_fd = unsafe {
                        libc::open(newdir_cpath.as_ptr(), libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    };
                    if newdir_fd < 0 {
                        None
                    } else {
                        let grabbed = self.grab_unlinked_fd(newdir_fd, newname).ok();
                        unsafe { libc::close(newdir_fd) };
                        grabbed
                    }
                }
                Ok(InodeHandle::Fd(newdir_fd)) => self.grab_unlinked_fd(newdir_fd, newname).ok(),
                Err(_) => None,
            }
        } else {
            None
        };

        let res = unsafe { libc::renamex_np(old_cpath.as_ptr(), new_cpath.as_ptr(), mflags) };
        if res == 0 {
            // If the rename overwrote a tracked inode, hand its preserved fd to
            // the inode store so later ops resolve by fd, not the vanished path.
            // `store_unlinked_fd` takes ownership only when that inode is
            // tracked; close the fd ourselves otherwise so it is never leaked.
            if let Some(fd) = doomed_fd {
                match self.store_unlinked_fd(&ctx, fd) {
                    Ok(true) => {}
                    Ok(false) | Err(_) => unsafe {
                        libc::close(fd);
                    },
                }
            }

            if ((flags as i32) & bindings::LINUX_RENAME_WHITEOUT) != 0 {
                let (host_mode, complete) = match self.cfg.semantics {
                    PermissionSemantics::LinuxComplete => (0o600, true),
                    PermissionSemantics::LinuxSimplified => {
                        (((libc::S_IFCHR | 0o600) as u32), false)
                    }
                    PermissionSemantics::Sandbox(_) => unreachable!(),
                };
                let fd = unsafe {
                    libc::open(
                        old_cpath.as_ptr(),
                        libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                        host_mode,
                    )
                };
                if fd > 0 {
                    if complete
                        && let Err(e) = set_stat(
                            &ctx,
                            self.cfg.semantics,
                            &InodeHandle::Fd(fd),
                            None,
                            None,
                            Some((libc::S_IFCHR | 0o600) as u32),
                        )
                    {
                        unsafe { libc::close(fd) };
                        return Err(e);
                    }

                    unsafe { libc::close(fd) };
                }
            }

            let entry = self.lookup(ctx, newdir, newname)?;
            self.forget(ctx, entry.inode, 1);

            Ok(())
        } else {
            if let Some(fd) = doomed_fd {
                // The rename failed; nothing was overwritten. Drop the fd.
                unsafe { libc::close(fd) };
            }
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn mknod(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        match self.cfg.semantics {
            PermissionSemantics::LinuxComplete => {
                self.mknod_complete(ctx, parent, name, mode, rdev, umask, extensions)
            }
            PermissionSemantics::LinuxSimplified => {
                self.mknod_simplified(ctx, parent, name, mode, rdev, umask, extensions)
            }
            PermissionSemantics::Sandbox(_) => {
                self.mknod_sandbox(ctx, parent, name, mode, umask, extensions)
            }
        }
    }

    fn link(
        &self,
        ctx: Context,
        inode: Inode,
        newparent: Inode,
        newname: &CStr,
    ) -> io::Result<Entry> {
        let orig_c_path = match self.inode_to_handle(inode, false)? {
            InodeHandle::Path(c_path) => c_path,
            InodeHandle::Fd(_) => return Err(ebadf()),
        };
        let link_c_path = self.name_to_path(newparent, newname)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::link(orig_c_path.as_ptr(), link_c_path.as_ptr()) };
        if res == 0 {
            self.lookup(ctx, newparent, newname)
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: Inode,
        name: &CStr,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        if matches!(self.cfg.semantics, PermissionSemantics::Sandbox(_))
            && extensions.secctx.is_some()
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EOPNOTSUPP)));
        }
        let c_path = self.name_to_path(parent, name)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::symlink(linkname.as_ptr(), c_path.as_ptr()) };
        if res == 0 {
            let ihandle = InodeHandle::Path(c_path.clone());

            // Set security context
            if let Some(secctx) = extensions.secctx {
                set_secctx(&ihandle, secctx, true)?
            };

            if matches!(
                self.cfg.semantics,
                PermissionSemantics::LinuxComplete | PermissionSemantics::Sandbox(_)
            ) {
                let mode = libc::S_IFLNK | 0o777;
                if let Err(error) = set_stat(
                    &ctx,
                    self.cfg.semantics,
                    &ihandle,
                    None,
                    Some((ctx.uid, ctx.gid)),
                    Some(mode as u32),
                ) {
                    if matches!(self.cfg.semantics, PermissionSemantics::Sandbox(_)) {
                        // Symlinks cannot be unlinked through an identity-bound
                        // handle. Avoid deleting a host replacement at the
                        // same path after the metadata failure.
                        warn!(
                            "symlink metadata attachment failed; a native host entry may remain: {error}"
                        );
                    }
                    return Err(error);
                }
            }
            let mut entry = self.lookup(ctx, parent, name)?;
            if matches!(
                self.cfg.semantics,
                PermissionSemantics::LinuxComplete | PermissionSemantics::Sandbox(_)
            ) {
                let mode = libc::S_IFLNK | 0o777;
                entry.attr.st_uid = ctx.uid;
                entry.attr.st_gid = ctx.gid;
                entry.attr.st_mode = mode;
            }
            Ok(entry)
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn readlink(&self, _ctx: Context, inode: Inode) -> io::Result<Vec<u8>> {
        let mut buf = vec![0; libc::PATH_MAX as usize];

        let res = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => unsafe {
                libc::readlink(
                    c_path.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len(),
                )
            },
            InodeHandle::Fd(fd) => unsafe {
                libc::freadlink(fd, buf.as_mut_ptr() as *mut libc::c_char, buf.len()) as isize
            },
        };
        if res < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        buf.resize(res as usize, 0);
        Ok(buf)
    }

    fn flush(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        _lock_owner: u64,
    ) -> io::Result<()> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        // Since this method is called whenever an fd is closed in the client, we can emulate that
        // behavior by doing the same thing (dup-ing the fd and then immediately closing it). Safe
        // because this doesn't modify any memory and we check the return values.
        unsafe {
            let newfd = libc::dup(data.file.write().unwrap().as_raw_fd());
            if newfd < 0 {
                return Err(linux_error(io::Error::last_os_error()));
            }

            if libc::close(newfd) < 0 {
                Err(linux_error(io::Error::last_os_error()))
            } else {
                Ok(())
            }
        }
    }

    fn fsync(
        &self,
        _ctx: Context,
        inode: Inode,
        _datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        let fd = data.file.write().unwrap().as_raw_fd();

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::fsync(fd) };

        if res == 0 {
            Ok(())
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn fsyncdir(
        &self,
        ctx: Context,
        inode: Inode,
        datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        self.fsync(ctx, inode, datasync, handle)
    }

    fn access(&self, ctx: Context, inode: Inode, mask: u32) -> io::Result<()> {
        let st = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => lstat(&ctx, self.cfg.semantics, &c_path, false)?,
            InodeHandle::Fd(fd) => fstat(&ctx, self.cfg.semantics, fd, false)?,
        };

        let mode = mask as i32 & (libc::R_OK | libc::W_OK | libc::X_OK);

        if mode == libc::F_OK {
            // The file exists since we were able to call `stat(2)` on it.
            return Ok(());
        }

        // We use ctx.uid/ctx.gid for these checks, but when idmapped mounts
        // support is enabled on the guest side, it means that "default_permissions"
        // flag is set on virtiofs mount and FUSE_ACCESS request should never be
        // sent to the userspace. Please, refer to the kernel commit
        // ("fs/fuse: warn if fuse_access is called when idmapped mounts are allowed").
        // In case when idmapped mounts are not enabled we are good to rely on ctx.uid/ctx.gid values.

        if (mode & libc::R_OK) != 0
            && ctx.uid != 0
            && (st.st_uid != ctx.uid || st.st_mode & 0o400 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o040 == 0)
            && st.st_mode & 0o004 == 0
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
        }

        if (mode & libc::W_OK) != 0
            && ctx.uid != 0
            && (st.st_uid != ctx.uid || st.st_mode & 0o200 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o020 == 0)
            && st.st_mode & 0o002 == 0
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
        }

        // root can only execute something if it is executable by one of the owner, the group, or
        // everyone.
        if (mode & libc::X_OK) != 0
            && (ctx.uid != 0 || st.st_mode & 0o111 == 0)
            && (st.st_uid != ctx.uid || st.st_mode & 0o100 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o010 == 0)
            && st.st_mode & 0o001 == 0
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
        }

        Ok(())
    }

    fn setxattr(
        &self,
        ctx: Context,
        inode: Inode,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        debug!("setxattr: inode={inode} name={name:?} value={value:?}");

        if !self.cfg.xattr {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        if let PermissionSemantics::Sandbox(config) = self.cfg.semantics {
            if !config.xattrs_enabled {
                return Err(linux_error(io::Error::from_raw_os_error(libc::EOPNOTSUPP)));
            }
            return self.sandbox_setxattr(&ctx, config.identity, inode, name, value, flags);
        }

        if name.to_bytes() == XATTR_KEY {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
        }

        if name.to_bytes().starts_with(MACOS_XATTR_PREFIX) {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EOPNOTSUPP)));
        }

        let mut mflags: i32 = 0;
        if (flags as i32) & bindings::LINUX_XATTR_CREATE != 0 {
            mflags |= libc::XATTR_CREATE;
        }
        if (flags as i32) & bindings::LINUX_XATTR_REPLACE != 0 {
            mflags |= libc::XATTR_REPLACE;
        }

        // Safe because this doesn't modify any memory and we check the return value.
        let res = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => unsafe {
                libc::setxattr(
                    c_path.as_ptr(),
                    name.as_ptr(),
                    value.as_ptr() as *const libc::c_void,
                    value.len(),
                    0,
                    mflags as libc::c_int,
                )
            },
            InodeHandle::Fd(fd) => unsafe {
                libc::fsetxattr(
                    fd,
                    name.as_ptr(),
                    value.as_ptr() as *const libc::c_void,
                    value.len(),
                    0,
                    mflags as libc::c_int,
                )
            },
        };

        if res == 0 {
            Ok(())
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn getxattr(
        &self,
        ctx: Context,
        inode: Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        debug!("getxattr: inode={inode} name={name:?}, size={size}");

        if !self.cfg.xattr {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        if let PermissionSemantics::Sandbox(config) = self.cfg.semantics {
            if !config.xattrs_enabled {
                return Err(linux_error(io::Error::from_raw_os_error(libc::EOPNOTSUPP)));
            }
            return self.sandbox_getxattr(&ctx, config.identity, inode, name, size);
        }

        if name.to_bytes() == XATTR_KEY {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
        }

        if name.to_bytes().starts_with(MACOS_XATTR_PREFIX) {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENODATA)));
        }

        let mut buf = vec![0; size as usize];

        // Safe because this will only modify the contents of `buf`
        let res = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => unsafe {
                if size == 0 {
                    libc::getxattr(
                        c_path.as_ptr(),
                        name.as_ptr(),
                        std::ptr::null_mut(),
                        size as libc::size_t,
                        0,
                        0,
                    )
                } else {
                    libc::getxattr(
                        c_path.as_ptr(),
                        name.as_ptr(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        size as libc::size_t,
                        0,
                        0,
                    )
                }
            },
            InodeHandle::Fd(fd) => unsafe {
                if size == 0 {
                    libc::fgetxattr(
                        fd,
                        name.as_ptr(),
                        std::ptr::null_mut(),
                        size as libc::size_t,
                        0,
                        0,
                    )
                } else {
                    libc::fgetxattr(
                        fd,
                        name.as_ptr(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        size as libc::size_t,
                        0,
                        0,
                    )
                }
            },
        };
        if res < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        if size == 0 {
            Ok(GetxattrReply::Count(res as u32))
        } else {
            buf.resize(res as usize, 0);
            Ok(GetxattrReply::Value(buf))
        }
    }

    fn listxattr(&self, ctx: Context, inode: Inode, size: u32) -> io::Result<ListxattrReply> {
        if !self.cfg.xattr {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        if let PermissionSemantics::Sandbox(config) = self.cfg.semantics {
            if !config.xattrs_enabled {
                return Err(linux_error(io::Error::from_raw_os_error(libc::EOPNOTSUPP)));
            }
            return self.sandbox_listxattr(&ctx, config.identity, inode, size);
        }

        let mut buf = vec![0; 512_usize];

        // Safe because this will only modify the contents of `buf`.
        let res = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => unsafe {
                libc::listxattr(
                    c_path.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_char,
                    512,
                    0,
                )
            },
            InodeHandle::Fd(fd) => unsafe {
                libc::flistxattr(fd, buf.as_mut_ptr() as *mut libc::c_char, 512, 0)
            },
        };
        if res < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        buf.truncate(res as usize);

        if size == 0 {
            let mut clean_size = res as usize;

            for attr in buf.split(|c| *c == 0) {
                if attr.starts_with(&XATTR_KEY[..XATTR_KEY.len() - 1]) {
                    clean_size -= XATTR_KEY.len();
                } else if attr.starts_with(MACOS_XATTR_PREFIX) {
                    // attr does not include the null terminator; add 1 for it.
                    clean_size -= attr.len() + 1;
                }
            }

            Ok(ListxattrReply::Count(clean_size as u32))
        } else {
            let mut clean_buf = Vec::new();

            for attr in buf.split(|c| *c == 0) {
                if attr.is_empty()
                    || attr.starts_with(&XATTR_KEY[..XATTR_KEY.len() - 1])
                    || attr.starts_with(MACOS_XATTR_PREFIX)
                {
                    continue;
                }

                clean_buf.extend_from_slice(attr);
                clean_buf.push(0);
            }

            clean_buf.shrink_to_fit();

            if clean_buf.len() > size as usize {
                Err(io::Error::from_raw_os_error(LINUX_ERANGE))
            } else {
                Ok(ListxattrReply::Names(clean_buf))
            }
        }
    }

    fn removexattr(&self, ctx: Context, inode: Inode, name: &CStr) -> io::Result<()> {
        if !self.cfg.xattr {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        if let PermissionSemantics::Sandbox(config) = self.cfg.semantics {
            if !config.xattrs_enabled {
                return Err(linux_error(io::Error::from_raw_os_error(libc::EOPNOTSUPP)));
            }
            return self.sandbox_removexattr(&ctx, config.identity, inode, name);
        }

        if name.to_bytes() == XATTR_KEY {
            return Err(linux_error(io::Error::from_raw_os_error(
                bindings::LINUX_EACCES,
            )));
        }

        if name.to_bytes().starts_with(MACOS_XATTR_PREFIX) {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENODATA)));
        }

        // Safe because this doesn't modify any memory and we check the return value.
        let res = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => unsafe {
                libc::removexattr(c_path.as_ptr(), name.as_ptr(), 0)
            },
            InodeHandle::Fd(fd) => unsafe { libc::fremovexattr(fd, name.as_ptr(), 0) },
        };
        if res == 0 {
            Ok(())
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn fallocate(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        let fd = data.file.write().unwrap().as_raw_fd();

        const SUPPORTED_FLAGS: i32 = bindings::LINUX_FALLOC_FL_ALLOCATE_RANGE
            | bindings::LINUX_FALLOC_FL_KEEP_SIZE
            | bindings::LINUX_FALLOC_FL_PUNCH_HOLE;

        if mode as i32 & !SUPPORTED_FLAGS != 0 {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EOPNOTSUPP)));
        }

        let keep_size = mode & bindings::LINUX_FALLOC_FL_KEEP_SIZE as u32 != 0;
        let mode = mode & !bindings::LINUX_FALLOC_FL_KEEP_SIZE as u32;

        match mode as i32 {
            bindings::LINUX_FALLOC_FL_ALLOCATE_RANGE => {
                // The closest thing we have on macOS to posix_fallocate is F_PREALLOCATE,
                // but this one doesn't allow us to allocate arbitrary ranges, only allocate
                // blocks to the file's end.
                //
                // The best thing we can do here is extend the file to (offset + length).
                // This doesn't adhere to the same semantics, but should work fine (albeit
                // less performant) for most guest applications.
                let st = fstat(&ctx, self.cfg.semantics, fd, true)?;
                let new_length = (offset + length) as i64;

                if keep_size {
                    // Check the number of allocated blocks instead of the file size.
                    let disk_size = st.st_blocks * 512_i64;
                    if disk_size >= new_length {
                        return Ok(());
                    }
                    let mut fs = libc::fstore_t {
                        fst_flags: libc::F_ALLOCATEALL,
                        fst_posmode: libc::F_PEOFPOSMODE,
                        fst_offset: 0,
                        fst_length: new_length - disk_size,
                        fst_bytesalloc: 0,
                    };

                    let res = unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &mut fs as *mut _) };
                    if res < 0 {
                        return Err(linux_error(io::Error::last_os_error()));
                    }
                } else {
                    if st.st_size >= new_length {
                        return Ok(());
                    }
                    let res = unsafe { libc::ftruncate(fd, new_length) };
                    if res < 0 {
                        return Err(linux_error(io::Error::last_os_error()));
                    }
                }
            }
            bindings::LINUX_FALLOC_FL_PUNCH_HOLE => {
                if !keep_size {
                    // Linux forbids the use of PUNCH_HOLE without KEEP_SIZE.
                    return Err(linux_error(io::Error::from_raw_os_error(libc::EINVAL)));
                }

                let mut hole = libc::fpunchhole_t {
                    fp_offset: offset as i64,
                    fp_flags: 0,
                    reserved: 0,
                    fp_length: length as i64,
                };

                let res = unsafe { libc::fcntl(fd, libc::F_PUNCHHOLE, &mut hole as *mut _) };
                if res < 0 {
                    return Err(linux_error(io::Error::last_os_error()));
                }
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    fn lseek(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        // SEEK_DATA and SEEK_HOLE have slightly different semantics
        // in Linux vs. macOS, which means we can't support them.
        let mwhence = if whence == 3 {
            // SEEK_DATA
            return Ok(offset);
        } else if whence == 4 {
            // SEEK_HOLE
            libc::SEEK_END
        } else {
            whence as i32
        };

        let fd = data.file.write().unwrap().as_raw_fd();

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::lseek(fd, offset as bindings::off64_t, mwhence as libc::c_int) };
        if res < 0 {
            Err(linux_error(io::Error::last_os_error()))
        } else {
            Ok(res as u64)
        }
    }

    fn setupmapping(
        &self,
        _ctx: Context,
        inode: Inode,
        _handle: Handle,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        guest_shm_base: u64,
        shm_size: u64,
        map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        if map_sender.is_none() {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        let open_flags = if (flags & fuse::SetupmappingFlags::WRITE.bits()) != 0 {
            libc::O_RDWR
        } else {
            libc::O_RDONLY
        };

        let prot_flags = if (flags & fuse::SetupmappingFlags::WRITE.bits()) != 0 {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };

        if (moffset + len) > shm_size {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EINVAL)));
        }

        let guest_addr = guest_shm_base + moffset;

        debug!("setupmapping: ino {inode:?} guest_addr={guest_addr:x} len={len}");

        let file = self.open_inode(inode, open_flags)?;
        let fd = file.as_raw_fd();

        let host_addr = unsafe {
            libc::mmap(
                null_mut(),
                len as usize,
                prot_flags,
                libc::MAP_SHARED,
                fd,
                foffset as libc::off_t,
            )
        };
        if host_addr == libc::MAP_FAILED {
            return Err(linux_error(io::Error::last_os_error()));
        }

        drop(file);

        // We've checked that map_sender is something above.
        let sender = map_sender.as_ref().unwrap();
        let (reply_sender, reply_receiver) = unbounded();
        sender
            .send(WorkerMessage::GpuAddMapping(
                reply_sender,
                host_addr as u64,
                guest_addr,
                len,
            ))
            .unwrap();
        if !reply_receiver.recv().unwrap() {
            error!("Error requesting HVF the addition of a DAX window");
            unsafe { libc::munmap(host_addr, len as usize) };
            return Err(linux_error(io::Error::from_raw_os_error(libc::EINVAL)));
        }

        self.map_windows
            .lock()
            .unwrap()
            .insert(guest_addr, host_addr as u64);

        Ok(())
    }

    fn removemapping(
        &self,
        _ctx: Context,
        requests: Vec<fuse::RemovemappingOne>,
        guest_shm_base: u64,
        shm_size: u64,
        map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        if map_sender.is_none() {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        for req in requests {
            let guest_addr = guest_shm_base + req.moffset;
            if (req.moffset + req.len) > shm_size {
                return Err(linux_error(io::Error::from_raw_os_error(libc::EINVAL)));
            }
            let host_addr = match self.map_windows.lock().unwrap().remove(&guest_addr) {
                Some(a) => a,
                None => return Err(linux_error(io::Error::from_raw_os_error(libc::EINVAL))),
            };
            debug!(
                "removemapping: guest_addr={:x} len={:?}",
                guest_addr, req.len
            );

            let sender = map_sender.as_ref().unwrap();
            let (reply_sender, reply_receiver) = unbounded();
            sender
                .send(WorkerMessage::GpuRemoveMapping(
                    reply_sender,
                    guest_addr,
                    req.len,
                ))
                .unwrap();
            if !reply_receiver.recv().unwrap() {
                error!("Error requesting HVF the removal of a DAX window");
                return Err(linux_error(io::Error::from_raw_os_error(libc::EINVAL)));
            }

            let ret = unsafe { libc::munmap(host_addr as *mut libc::c_void, req.len as usize) };
            if ret == -1 {
                error!("Error unmapping DAX window");
                return Err(linux_error(io::Error::last_os_error()));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::{env, process};

    use super::*;

    static NEXT_TEMP_TREE: AtomicU64 = AtomicU64::new(0);

    struct TempTree {
        path: PathBuf,
    }

    impl TempTree {
        fn new(name: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = env::temp_dir().join(format!(
                "krun-macos-passthrough-{name}-{}-{unique}-{}",
                process::id(),
                NEXT_TEMP_TREE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn c_path(&self, name: &str) -> CString {
            CString::new(self.path.join(name).to_string_lossy().as_bytes()).unwrap()
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn context() -> Context {
        Context {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            pid: 0,
        }
    }

    fn sandbox_config(xattrs_enabled: bool) -> SandboxConfig {
        SandboxConfig {
            identity: IdentityMapping {
                host_uid: unsafe { libc::geteuid() },
                host_gid: unsafe { libc::getegid() },
                guest_uid: 0,
                guest_gid: 0,
            },
            xattrs_enabled,
        }
    }

    fn v2_capability() -> Vec<u8> {
        let mut capability = vec![0; 20];
        capability[..4].copy_from_slice(&0x0200_0000_u32.to_le_bytes());
        capability
    }

    #[test]
    fn sandbox_does_not_negotiate_security_contexts() {
        let root = TempTree::new("security-context");
        let capable = FsOptions::SECURITY_CTX;
        let native = PassthroughFs::new(
            Config {
                root_dir: root.path.to_string_lossy().into_owned(),
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        assert!(
            native
                .init(capable)
                .unwrap()
                .contains(FsOptions::SECURITY_CTX)
        );

        let sandbox = PassthroughFs::new(
            Config {
                root_dir: root.path.to_string_lossy().into_owned(),
                semantics: PermissionSemantics::Sandbox(sandbox_config(true)),
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        assert!(
            !sandbox
                .init(capable)
                .unwrap()
                .contains(FsOptions::SECURITY_CTX)
        );
    }

    #[test]
    fn sandbox_rejects_guest_identity_that_collides_with_overflow() {
        let root = TempTree::new("overflow-identity");
        for identity in [
            IdentityMapping {
                guest_uid: OVERFLOW_ID,
                ..sandbox_config(true).identity
            },
            IdentityMapping {
                guest_gid: OVERFLOW_ID,
                ..sandbox_config(true).identity
            },
        ] {
            let result = PassthroughFs::new(
                Config {
                    root_dir: root.path.to_string_lossy().into_owned(),
                    semantics: PermissionSemantics::Sandbox(SandboxConfig {
                        identity,
                        xattrs_enabled: true,
                    }),
                    ..Default::default()
                },
                Arc::new(InodeAllocator::new()),
            );
            let error = match result {
                Ok(_) => panic!("overflow identity unexpectedly accepted"),
                Err(error) => error,
            };
            assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
        }
    }

    #[test]
    fn native_only_mode_does_not_hide_existing_metadata() {
        let root = TempTree::new("existing-metadata");
        let path = root.c_path("adopted");
        fs::write(root.path.join("adopted"), "contents").unwrap();
        let ctx = context();
        let host_st = lstat(&ctx, PermissionSemantics::LinuxComplete, &path, true).unwrap();
        write_sandbox_metadata(
            &InodeHandle::Path(path.clone()),
            host_st,
            &GuestMetadata {
                uid: 123,
                gid: 456,
                mode: libc::S_IFREG as u32 | 0o640,
                capability: None,
            },
        )
        .unwrap();

        let st = lstat(
            &ctx,
            PermissionSemantics::Sandbox(sandbox_config(false)),
            &path,
            false,
        )
        .unwrap();
        assert_eq!((st.st_uid, st.st_gid), (123, 456));
        assert_eq!(st.st_mode as u32 & 0o7777, 0o640);
    }

    #[test]
    fn native_only_content_mutation_succeeds_when_metadata_is_unchanged() {
        let root = TempTree::new("native-content");
        let path = root.c_path("native");
        fs::write(root.path.join("native"), "contents").unwrap();

        prepare_sandbox_content_mutation(
            &context(),
            sandbox_config(false),
            &InodeHandle::Path(path.clone()),
            false,
        )
        .unwrap();

        let host_st = lstat(&context(), PermissionSemantics::LinuxComplete, &path, true).unwrap();
        assert_eq!(
            read_sandbox_metadata(&InodeHandle::Path(path), host_st).unwrap(),
            None
        );
    }

    #[test]
    fn native_only_create_succeeds_when_native_metadata_matches() {
        let root = TempTree::new("native-create");
        let passthrough = PassthroughFs::new(
            Config {
                root_dir: root.path.to_string_lossy().into_owned(),
                semantics: PermissionSemantics::Sandbox(sandbox_config(false)),
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        passthrough.init(FsOptions::empty()).unwrap();
        let name = CString::new("native").unwrap();
        let guest_root = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };

        let entry = passthrough
            .mknod(
                guest_root,
                fuse::ROOT_ID,
                &name,
                libc::S_IFREG as u32 | 0o600,
                0,
                0,
                Extensions::default(),
            )
            .unwrap();

        assert_eq!((entry.attr.st_uid, entry.attr.st_gid), (0, 0));
        assert_eq!(entry.attr.st_mode as u32 & 0o7777, 0o600);
        let path = root.c_path("native");
        let host_st = lstat(&context(), PermissionSemantics::LinuxComplete, &path, true).unwrap();
        assert_eq!(
            read_sandbox_metadata(&InodeHandle::Path(path), host_st).unwrap(),
            None
        );
    }

    #[test]
    fn opened_stat_ignores_path_replacement() {
        let root = TempTree::new("stat-replacement");
        let path = root.c_path("file");
        fs::write(root.path.join("file"), "opened").unwrap();
        let ctx = context();
        let original_host_st =
            lstat(&ctx, PermissionSemantics::LinuxComplete, &path, true).unwrap();
        write_sandbox_metadata(
            &InodeHandle::Path(path.clone()),
            original_host_st,
            &GuestMetadata {
                uid: 123,
                gid: 456,
                mode: libc::S_IFREG as u32 | 0o640,
                capability: None,
            },
        )
        .unwrap();
        let file = open_sandbox_stat(&path).unwrap();

        fs::rename(root.path.join("file"), root.path.join("detached")).unwrap();
        fs::write(root.path.join("file"), "replacement").unwrap();
        let replacement_st = lstat(&ctx, PermissionSemantics::LinuxComplete, &path, true).unwrap();

        let st = fstat(
            &ctx,
            PermissionSemantics::Sandbox(sandbox_config(true)),
            file.as_raw_fd(),
            false,
        )
        .unwrap();
        assert_eq!((st.st_uid, st.st_gid), (123, 456));
        assert_eq!(st.st_mode as u32 & 0o7777, 0o640);
        assert_eq!(
            (st.st_dev, st.st_ino),
            (original_host_st.st_dev, original_host_st.st_ino)
        );
        assert_ne!(
            (st.st_dev, st.st_ino),
            (replacement_st.st_dev, replacement_st.st_ino)
        );
    }

    #[test]
    fn sandbox_lstat_reads_symlink_metadata_from_open_descriptor() {
        let root = TempTree::new("symlink-stat");
        let path = root.c_path("link");
        symlink("target", root.path.join("link")).unwrap();
        let ctx = context();
        let host_st = lstat(&ctx, PermissionSemantics::LinuxComplete, &path, true).unwrap();
        write_sandbox_metadata(
            &InodeHandle::Path(path.clone()),
            host_st,
            &GuestMetadata {
                uid: 123,
                gid: 456,
                mode: libc::S_IFLNK as u32 | 0o777,
                capability: None,
            },
        )
        .unwrap();

        let st = lstat(
            &ctx,
            PermissionSemantics::Sandbox(sandbox_config(true)),
            &path,
            false,
        )
        .unwrap();
        assert_eq!((st.st_uid, st.st_gid), (123, 456));
        assert_eq!(
            st.st_mode as u32 & libc::S_IFMT as u32,
            libc::S_IFLNK as u32
        );
    }

    #[test]
    fn sandbox_lstat_rejects_fifo_without_blocking() {
        assert_ne!(SANDBOX_STAT_OPEN_FLAGS & libc::O_NONBLOCK, 0);
        let root = TempTree::new("fifo-stat");
        let path = root.c_path("fifo");
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);

        let error = lstat(
            &context(),
            PermissionSemantics::Sandbox(sandbox_config(true)),
            &path,
            false,
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(LINUX_EOPNOTSUPP));
    }

    #[test]
    fn content_mutation_clears_capability_without_kill_priv() {
        let root = TempTree::new("content-capability");
        let path = root.c_path("capable");
        fs::write(root.path.join("capable"), "contents").unwrap();
        let ctx = context();
        let host_st = lstat(&ctx, PermissionSemantics::LinuxComplete, &path, true).unwrap();
        write_sandbox_metadata(
            &InodeHandle::Path(path.clone()),
            host_st,
            &GuestMetadata {
                uid: 0,
                gid: 0,
                mode: libc::S_IFREG as u32 | 0o755,
                capability: Some(v2_capability()),
            },
        )
        .unwrap();

        prepare_sandbox_content_mutation(
            &ctx,
            sandbox_config(true),
            &InodeHandle::Path(path.clone()),
            false,
        )
        .unwrap();

        let metadata = read_sandbox_metadata(&InodeHandle::Path(path), host_st)
            .unwrap()
            .unwrap();
        assert_eq!(metadata.capability, None);
        assert_eq!(metadata.mode & 0o7777, 0o755);
    }

    #[test]
    fn create_truncate_applies_kill_priv_to_requested_mode() {
        let root = TempTree::new("create-kill-priv");
        let fs = PassthroughFs::new(
            Config {
                root_dir: root.path.to_string_lossy().into_owned(),
                semantics: PermissionSemantics::Sandbox(sandbox_config(true)),
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        fs.init(FsOptions::HANDLE_KILLPRIV_V2).unwrap();
        let name = CString::new("created").unwrap();
        let flags = (bindings::LINUX_O_CREAT | bindings::LINUX_O_TRUNC | libc::O_WRONLY) as u32;

        let (entry, handle, _) = fs
            .create(
                context(),
                fuse::ROOT_ID,
                &name,
                0o6755,
                true,
                flags,
                0,
                Extensions::default(),
            )
            .unwrap();

        let path = root.c_path("created");
        let host_st = lstat(&context(), PermissionSemantics::LinuxComplete, &path, true).unwrap();
        let metadata = read_sandbox_metadata(&InodeHandle::Path(path), host_st)
            .unwrap()
            .unwrap();
        assert_eq!(metadata.mode & 0o7777, 0o755);

        fs.release(
            context(),
            entry.inode,
            flags,
            handle.unwrap(),
            false,
            false,
            None,
        )
        .unwrap();
    }

    #[test]
    fn sandbox_create_preserves_caller_exclusivity() {
        let root = TempTree::new("create");
        let path = root.c_path("file");

        let (fd, created) = open_sandbox_create(&path, libc::O_WRONLY, 0o600).unwrap();
        assert!(created);
        unsafe { libc::close(fd) };

        let (fd, created) = open_sandbox_create(&path, libc::O_WRONLY, 0o600).unwrap();
        assert!(!created);
        unsafe { libc::close(fd) };

        let error = open_sandbox_create(&path, libc::O_WRONLY | libc::O_EXCL, 0o600).unwrap_err();
        assert_eq!(
            error.raw_os_error(),
            linux_error(io::Error::from_raw_os_error(libc::EEXIST)).raw_os_error()
        );
    }

    #[test]
    fn opened_file_entry_ignores_path_replacement() {
        let root = TempTree::new("create-replacement");
        let passthrough = PassthroughFs::new(
            Config {
                root_dir: root.path.to_string_lossy().into_owned(),
                semantics: PermissionSemantics::Sandbox(sandbox_config(true)),
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        passthrough.init(FsOptions::empty()).unwrap();

        let path = root.path.join("file");
        fs::write(&path, "opened").unwrap();
        let file = File::open(&path).unwrap();
        let ctx = context();

        fs::rename(&path, root.path.join("detached")).unwrap();
        fs::write(&path, "replacement").unwrap();
        let opened_st = fstat(&ctx, passthrough.cfg.semantics, file.as_raw_fd(), false).unwrap();
        let replacement_st =
            lstat(&ctx, passthrough.cfg.semantics, &root.c_path("file"), false).unwrap();

        let entry = passthrough
            .entry_from_file(&ctx, fuse::ROOT_ID, &file)
            .unwrap();
        assert_eq!(
            (entry.attr.st_dev, entry.attr.st_ino),
            (opened_st.st_dev, opened_st.st_ino)
        );
        assert_ne!(
            (entry.attr.st_dev, entry.attr.st_ino),
            (replacement_st.st_dev, replacement_st.st_ino)
        );
        let registered = passthrough
            .inodes
            .read()
            .unwrap()
            .get(&entry.inode)
            .cloned()
            .unwrap();
        assert_eq!(
            (registered.dev, registered.ino),
            (opened_st.st_dev, opened_st.st_ino)
        );
    }

    #[test]
    fn metadata_attachment_failure_does_not_unlink_by_path() {
        let root = TempTree::new("metadata-failure");
        let fs = PassthroughFs::new(
            Config {
                root_dir: root.path.to_string_lossy().into_owned(),
                semantics: PermissionSemantics::Sandbox(sandbox_config(false)),
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        let name = CString::new("unadopted").unwrap();

        let error = match fs.mknod(
            context(),
            fuse::ROOT_ID,
            &name,
            libc::S_IFREG as u32 | 0o644,
            0,
            0,
            Extensions::default(),
        ) {
            Ok(_) => panic!("metadata attachment unexpectedly succeeded"),
            Err(error) => error,
        };

        assert_eq!(error.raw_os_error(), Some(LINUX_EOPNOTSUPP));
        assert!(root.path.join("unadopted").exists());
    }
}

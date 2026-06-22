use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr};
use std::hash::Hash;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::AtomicI32;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

#[cfg(target_os = "macos")]
use crossbeam_channel::Sender;
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;

use super::filesystem::{
    Context, DirEntry, Entry, Extensions, FileSystem, FsOptions, GetxattrReply, ListxattrReply,
    OpenOptions, RemovemappingOne, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};
use super::fuse;
use super::inode_alloc::InodeAllocator;
use super::passthrough::{self, PassthroughFs};
use crate::virtio::bindings;
use crate::virtio::linux_errno;

type Inode = u64;
type Handle = u64;

const SYNTHETIC_READDIR_OFFSET: u64 = 1 << 63;

#[derive(Clone, Debug)]
pub struct MaskConfig {
    pub paths: Vec<String>,
    pub storage: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Backend {
    Lower,
    Upper,
}

#[derive(Clone, Debug)]
struct Route {
    backend: Backend,
    path: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct MaskChild {
    name: Vec<u8>,
    path: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct MaskSet {
    paths: Vec<Vec<Vec<u8>>>,
    children_by_parent: HashMap<Vec<u8>, Vec<MaskChild>>,
    case_insensitive: bool,
}

pub struct MaskFs<L> {
    lower: L,
    upper: Option<PassthroughFs>,
    masks: MaskSet,
    routes: RwLock<HashMap<Inode, Route>>,
    path_inodes: RwLock<HashMap<(Backend, Vec<u8>), Inode>>,
}

impl MaskSet {
    fn new(paths: Vec<String>, case_insensitive: bool) -> Self {
        let paths = paths
            .into_iter()
            .map(|path| {
                path.trim_start_matches('/')
                    .split('/')
                    .filter(|component| !component.is_empty())
                    .map(|component| component.as_bytes().to_vec())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut children_by_parent: HashMap<Vec<u8>, Vec<MaskChild>> = HashMap::new();
        for path in &paths {
            if let Some((name, parent)) = path.split_last() {
                children_by_parent
                    .entry(path_key(parent))
                    .or_default()
                    .push(MaskChild {
                        name: name.clone(),
                        path: path.clone(),
                    });
            }
        }
        Self {
            paths,
            children_by_parent,
            case_insensitive,
        }
    }

    fn is_masked(&self, path: &[Vec<u8>]) -> bool {
        self.paths
            .iter()
            .any(|mask| path_starts_with(path, mask, self.case_insensitive))
    }

    fn direct_children(&self, parent: &[Vec<u8>]) -> &[MaskChild] {
        self.children_by_parent
            .get(&path_key(parent))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn is_direct_child(&self, parent: &[Vec<u8>], name: &[u8]) -> bool {
        self.direct_children(parent).iter().any(|child| {
            if self.case_insensitive {
                child.name.eq_ignore_ascii_case(name)
            } else {
                child.name == name
            }
        })
    }
}

impl<L: FileSystem<Inode = Inode, Handle = Handle>> MaskFs<L> {
    pub fn new(
        lower: L,
        config: MaskConfig,
        inode_alloc: Arc<InodeAllocator>,
        case_insensitive: bool,
    ) -> io::Result<Self> {
        let masks = MaskSet::new(config.paths, case_insensitive);
        let upper = if let Some(storage) = config.storage {
            std::fs::create_dir_all(&storage)?;
            for path in &masks.paths {
                if path.len() > 1 {
                    std::fs::create_dir_all(storage_path(&storage, &path[..path.len() - 1]))?;
                }
            }
            Some(PassthroughFs::new(
                passthrough::Config {
                    root_dir: storage,
                    entry_timeout: Duration::ZERO,
                    attr_timeout: Duration::ZERO,
                    ..Default::default()
                },
                inode_alloc,
            )?)
        } else {
            None
        };
        let mut routes = HashMap::new();
        routes.insert(
            fuse::ROOT_ID,
            Route {
                backend: Backend::Lower,
                path: Vec::new(),
            },
        );
        let mut path_inodes = HashMap::new();
        path_inodes.insert((Backend::Lower, Vec::new()), fuse::ROOT_ID);
        path_inodes.insert((Backend::Upper, Vec::new()), fuse::ROOT_ID);
        Ok(Self {
            lower,
            upper,
            masks,
            routes: RwLock::new(routes),
            path_inodes: RwLock::new(path_inodes),
        })
    }

    fn upper(&self) -> io::Result<&PassthroughFs> {
        self.upper
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EROFS))
    }

    fn route(&self, inode: Inode) -> io::Result<Route> {
        self.routes
            .read()
            .unwrap()
            .get(&inode)
            .cloned()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))
    }

    fn record(&self, backend: Backend, path: Vec<Vec<u8>>, inode: Inode) {
        self.routes.write().unwrap().insert(
            inode,
            Route {
                backend,
                path: path.clone(),
            },
        );
        self.path_inodes
            .write()
            .unwrap()
            .insert((backend, path_key(&path)), inode);
    }

    fn record_entry(&self, backend: Backend, path: Vec<Vec<u8>>, entry: &Entry) {
        self.record(backend, path, entry.inode);
    }

    fn route_child(&self, parent: &Route, name: &CStr) -> ChildRoute {
        let mut path = parent.path.clone();
        path.push(name.to_bytes().to_vec());
        if parent.backend == Backend::Upper {
            return ChildRoute::Upper { path };
        }
        if self.masks.is_masked(&path) {
            return ChildRoute::Upper { path };
        }
        ChildRoute::Lower { path }
    }

    fn upper_parent_inode(&self, ctx: Context, path: &[Vec<u8>]) -> io::Result<Inode> {
        if path.is_empty() {
            return Ok(fuse::ROOT_ID);
        }
        if let Some(inode) = self
            .path_inodes
            .read()
            .unwrap()
            .get(&(Backend::Upper, path_key(path)))
            .copied()
        {
            return Ok(inode);
        }
        let upper = self.upper()?;
        let mut parent = fuse::ROOT_ID;
        let mut current = Vec::with_capacity(path.len());
        for component in path {
            current.push(component.clone());
            if let Some(inode) = self
                .path_inodes
                .read()
                .unwrap()
                .get(&(Backend::Upper, path_key(&current)))
                .copied()
            {
                parent = inode;
                continue;
            }
            let name = CString::new(component.clone()).map_err(|_| linux_errno::einval())?;
            let entry = upper.lookup(ctx, parent, &name)?;
            parent = entry.inode;
            self.record_entry(Backend::Upper, current.clone(), &entry);
        }
        Ok(parent)
    }

    fn lookup_upper_path(&self, ctx: Context, path: &[Vec<u8>]) -> io::Result<Entry> {
        let (name, parent_path) = path.split_last().ok_or_else(linux_errno::einval)?;
        let parent = self.upper_parent_inode(ctx, parent_path)?;
        let name = CString::new(name.clone()).map_err(|_| linux_errno::einval())?;
        let entry = self.upper()?.lookup(ctx, parent, &name)?;
        self.record_entry(Backend::Upper, path.to_vec(), &entry);
        Ok(entry)
    }

    fn routed_parent(
        &self,
        ctx: Context,
        parent: &Route,
        target_path: &[Vec<u8>],
        backend: Backend,
    ) -> io::Result<Inode> {
        match backend {
            Backend::Lower => Ok(self
                .path_inodes
                .read()
                .unwrap()
                .get(&(Backend::Lower, path_key(&parent.path)))
                .copied()
                .unwrap_or(fuse::ROOT_ID)),
            Backend::Upper => {
                if parent.backend == Backend::Upper {
                    Ok(self
                        .path_inodes
                        .read()
                        .unwrap()
                        .get(&(Backend::Upper, path_key(&parent.path)))
                        .copied()
                        .unwrap_or(fuse::ROOT_ID))
                } else {
                    self.upper_parent_inode(ctx, &target_path[..target_path.len() - 1])
                }
            }
        }
    }

    fn entry_type(attr: bindings::stat64) -> u32 {
        match attr.st_mode as u32 & libc::S_IFMT as u32 {
            mode if mode == libc::S_IFDIR as u32 => libc::DT_DIR as u32,
            mode if mode == libc::S_IFLNK as u32 => libc::DT_LNK as u32,
            mode if mode == libc::S_IFCHR as u32 => libc::DT_CHR as u32,
            mode if mode == libc::S_IFBLK as u32 => libc::DT_BLK as u32,
            mode if mode == libc::S_IFIFO as u32 => libc::DT_FIFO as u32,
            mode if mode == libc::S_IFSOCK as u32 => libc::DT_SOCK as u32,
            mode if mode == libc::S_IFREG as u32 => libc::DT_REG as u32,
            _ => libc::DT_UNKNOWN as u32,
        }
    }

    fn add_upper_readdir_entries<F>(
        &self,
        ctx: Context,
        parent_path: &[Vec<u8>],
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry, Entry) -> io::Result<usize>,
    {
        if self.upper.is_none() {
            return Ok(());
        }
        let start = if offset & SYNTHETIC_READDIR_OFFSET != 0 {
            (offset - SYNTHETIC_READDIR_OFFSET) as usize
        } else {
            0
        };
        for (index, child) in self
            .masks
            .direct_children(parent_path)
            .iter()
            .enumerate()
            .skip(start)
        {
            let entry = match self.lookup_upper_path(ctx, &child.path) {
                Ok(entry) => entry,
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => continue,
                Err(error) => return Err(error),
            };
            let dir_entry = DirEntry {
                ino: entry.attr.st_ino,
                offset: SYNTHETIC_READDIR_OFFSET + index as u64 + 1,
                type_: Self::entry_type(entry.attr),
                name: &child.name,
            };
            if add_entry(dir_entry, entry)? == 0 {
                break;
            }
        }
        Ok(())
    }
}

enum ChildRoute {
    Lower { path: Vec<Vec<u8>> },
    Upper { path: Vec<Vec<u8>> },
}

impl<L: FileSystem<Inode = Inode, Handle = Handle>> FileSystem for MaskFs<L> {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        let lower = self.lower.init(capable)?;
        let opts = if let Some(upper) = &self.upper {
            let upper = upper.init(capable)?;
            lower & upper
        } else {
            lower
        };
        // MaskFs composes a lower filesystem with optional upper storage.  Plain readdir keeps
        // lookup routing under MaskFs control, while readdirplus lets the guest kernel cache
        // entries returned during directory scans with lookup counts attached.
        Ok(opts & !(FsOptions::DO_READDIRPLUS | FsOptions::READDIRPLUS_AUTO))
    }

    fn destroy(&self) {
        self.lower.destroy();
        if let Some(upper) = &self.upper {
            upper.destroy();
        }
    }

    fn lookup(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        let parent_route = self.route(parent)?;
        match self.route_child(&parent_route, name) {
            ChildRoute::Lower { path } => {
                let entry = self.lower.lookup(ctx, parent, name)?;
                self.record_entry(Backend::Lower, path, &entry);
                Ok(entry)
            }
            ChildRoute::Upper { path, .. } => {
                if self.upper.is_none() {
                    return Err(linux_errno::enoent());
                }
                self.lookup_upper_path(ctx, &path)
            }
        }
    }

    fn forget(&self, ctx: Context, inode: Inode, count: u64) {
        match self.route(inode).map(|route| route.backend) {
            Ok(Backend::Lower) | Err(_) => self.lower.forget(ctx, inode, count),
            Ok(Backend::Upper) => {
                if let Some(upper) = &self.upper {
                    upper.forget(ctx, inode, count);
                }
            }
        }
    }

    fn batch_forget(&self, ctx: Context, requests: Vec<(Inode, u64)>) {
        let mut lower = Vec::new();
        let mut upper_requests = Vec::new();
        for (inode, count) in requests {
            match self.route(inode).map(|route| route.backend) {
                Ok(Backend::Upper) => upper_requests.push((inode, count)),
                Ok(Backend::Lower) | Err(_) => lower.push((inode, count)),
            }
        }
        self.lower.batch_forget(ctx, lower);
        if let Some(upper) = &self.upper {
            upper.batch_forget(ctx, upper_requests);
        }
    }

    fn getattr(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Option<Handle>,
    ) -> io::Result<(bindings::stat64, Duration)> {
        match self.route(inode)?.backend {
            Backend::Lower => self.lower.getattr(ctx, inode, handle),
            Backend::Upper => self.upper()?.getattr(ctx, inode, handle),
        }
    }

    fn setattr(
        &self,
        ctx: Context,
        inode: Inode,
        attr: bindings::stat64,
        handle: Option<Handle>,
        valid: SetattrValid,
    ) -> io::Result<(bindings::stat64, Duration)> {
        match self.route(inode)?.backend {
            Backend::Lower => self.lower.setattr(ctx, inode, attr, handle, valid),
            Backend::Upper => self.upper()?.setattr(ctx, inode, attr, handle, valid),
        }
    }

    fn readlink(&self, ctx: Context, inode: Inode) -> io::Result<Vec<u8>> {
        match self.route(inode)?.backend {
            Backend::Lower => self.lower.readlink(ctx, inode),
            Backend::Upper => self.upper()?.readlink(ctx, inode),
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
        let parent_route = self.route(parent)?;
        match self.route_child(&parent_route, name) {
            ChildRoute::Lower { path } => {
                let entry = self
                    .lower
                    .symlink(ctx, linkname, parent, name, extensions)?;
                self.record_entry(Backend::Lower, path, &entry);
                Ok(entry)
            }
            ChildRoute::Upper { path, .. } => {
                let parent = self.upper_parent_inode(ctx, &path[..path.len() - 1])?;
                let entry = self
                    .upper()?
                    .symlink(ctx, linkname, parent, name, extensions)?;
                self.record_entry(Backend::Upper, path, &entry);
                Ok(entry)
            }
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
        let parent_route = self.route(parent)?;
        match self.route_child(&parent_route, name) {
            ChildRoute::Lower { path } => {
                let entry = self
                    .lower
                    .mknod(ctx, parent, name, mode, rdev, umask, extensions)?;
                self.record_entry(Backend::Lower, path, &entry);
                Ok(entry)
            }
            ChildRoute::Upper { path, .. } => {
                let parent = self.upper_parent_inode(ctx, &path[..path.len() - 1])?;
                let entry = self
                    .upper()?
                    .mknod(ctx, parent, name, mode, rdev, umask, extensions)?;
                self.record_entry(Backend::Upper, path, &entry);
                Ok(entry)
            }
        }
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
        let parent_route = self.route(parent)?;
        match self.route_child(&parent_route, name) {
            ChildRoute::Lower { path } => {
                let entry = self
                    .lower
                    .mkdir(ctx, parent, name, mode, umask, extensions)?;
                self.record_entry(Backend::Lower, path, &entry);
                Ok(entry)
            }
            ChildRoute::Upper { path, .. } => {
                let parent = self.upper_parent_inode(ctx, &path[..path.len() - 1])?;
                let entry = self
                    .upper()?
                    .mkdir(ctx, parent, name, mode, umask, extensions)?;
                self.record_entry(Backend::Upper, path, &entry);
                Ok(entry)
            }
        }
    }

    fn unlink(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.remove(ctx, parent, name, false)
    }

    fn rmdir(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.remove(ctx, parent, name, true)
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
        let old_parent = self.route(olddir)?;
        let new_parent = self.route(newdir)?;
        let old_child = self.route_child(&old_parent, oldname);
        let new_child = self.route_child(&new_parent, newname);
        let (old_backend, old_path) = child_backend_path(&old_child)?;
        let (new_backend, new_path) = child_backend_path(&new_child)?;
        if old_backend != new_backend {
            return Err(linux_errno::exdev());
        }
        match old_backend {
            Backend::Lower => self
                .lower
                .rename(ctx, olddir, oldname, newdir, newname, flags),
            Backend::Upper => {
                let olddir = self.routed_parent(ctx, &old_parent, &old_path, Backend::Upper)?;
                let newdir = self.routed_parent(ctx, &new_parent, &new_path, Backend::Upper)?;
                self.upper()?
                    .rename(ctx, olddir, oldname, newdir, newname, flags)
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
        let source = self.route(inode)?;
        let parent = self.route(newparent)?;
        let child = self.route_child(&parent, newname);
        let (target_backend, target_path) = child_backend_path(&child)?;
        if source.backend != target_backend {
            return Err(linux_errno::exdev());
        }
        match source.backend {
            Backend::Lower => {
                let entry = self.lower.link(ctx, inode, newparent, newname)?;
                self.record_entry(Backend::Lower, target_path, &entry);
                Ok(entry)
            }
            Backend::Upper => {
                let newparent = self.routed_parent(ctx, &parent, &target_path, Backend::Upper)?;
                let entry = self.upper()?.link(ctx, inode, newparent, newname)?;
                self.record_entry(Backend::Upper, target_path, &entry);
                Ok(entry)
            }
        }
    }

    fn open(
        &self,
        ctx: Context,
        inode: Inode,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        match self.route(inode)?.backend {
            Backend::Lower => self.lower.open(ctx, inode, kill_priv, flags),
            Backend::Upper => self.upper()?.open(ctx, inode, kill_priv, flags),
        }
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
        let parent_route = self.route(parent)?;
        match self.route_child(&parent_route, name) {
            ChildRoute::Lower { path } => {
                let (entry, handle, options) = self
                    .lower
                    .create(ctx, parent, name, mode, kill_priv, flags, umask, extensions)?;
                self.record_entry(Backend::Lower, path, &entry);
                Ok((entry, handle, options))
            }
            ChildRoute::Upper { path, .. } => {
                let parent = self.upper_parent_inode(ctx, &path[..path.len() - 1])?;
                let (entry, handle, options) = self
                    .upper()?
                    .create(ctx, parent, name, mode, kill_priv, flags, umask, extensions)?;
                self.record_entry(Backend::Upper, path, &entry);
                Ok((entry, handle, options))
            }
        }
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        w: W,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> io::Result<usize> {
        match self.route(inode)?.backend {
            Backend::Lower => self
                .lower
                .read(ctx, inode, handle, w, size, offset, lock_owner, flags),
            Backend::Upper => self
                .upper()?
                .read(ctx, inode, handle, w, size, offset, lock_owner, flags),
        }
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        r: R,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<usize> {
        match self.route(inode)?.backend {
            Backend::Lower => self.lower.write(
                ctx,
                inode,
                handle,
                r,
                size,
                offset,
                lock_owner,
                delayed_write,
                kill_priv,
                flags,
            ),
            Backend::Upper => self.upper()?.write(
                ctx,
                inode,
                handle,
                r,
                size,
                offset,
                lock_owner,
                delayed_write,
                kill_priv,
                flags,
            ),
        }
    }

    fn flush(&self, ctx: Context, inode: Inode, handle: Handle, lock_owner: u64) -> io::Result<()> {
        match self.route(inode)?.backend {
            Backend::Lower => self.lower.flush(ctx, inode, handle, lock_owner),
            Backend::Upper => self.upper()?.flush(ctx, inode, handle, lock_owner),
        }
    }

    fn fsync(&self, ctx: Context, inode: Inode, datasync: bool, handle: Handle) -> io::Result<()> {
        match self.route(inode)?.backend {
            Backend::Lower => self.lower.fsync(ctx, inode, datasync, handle),
            Backend::Upper => self.upper()?.fsync(ctx, inode, datasync, handle),
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
        match self.route(inode)?.backend {
            Backend::Lower => self
                .lower
                .fallocate(ctx, inode, handle, mode, offset, length),
            Backend::Upper => self
                .upper()?
                .fallocate(ctx, inode, handle, mode, offset, length),
        }
    }

    fn release(
        &self,
        ctx: Context,
        inode: Inode,
        flags: u32,
        handle: Handle,
        flush: bool,
        flock_release: bool,
        lock_owner: Option<u64>,
    ) -> io::Result<()> {
        match self.route(inode)?.backend {
            Backend::Lower => {
                self.lower
                    .release(ctx, inode, flags, handle, flush, flock_release, lock_owner)
            }
            Backend::Upper => {
                self.upper()?
                    .release(ctx, inode, flags, handle, flush, flock_release, lock_owner)
            }
        }
    }

    fn statfs(&self, ctx: Context, inode: Inode) -> io::Result<bindings::statvfs64> {
        match self.route(inode)?.backend {
            Backend::Lower => self.lower.statfs(ctx, inode),
            Backend::Upper => self.upper()?.statfs(ctx, inode),
        }
    }

    fn setxattr(
        &self,
        ctx: Context,
        inode: Inode,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        match self.route(inode)?.backend {
            Backend::Lower => self.lower.setxattr(ctx, inode, name, value, flags),
            Backend::Upper => self.upper()?.setxattr(ctx, inode, name, value, flags),
        }
    }

    fn getxattr(
        &self,
        ctx: Context,
        inode: Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        match self.route(inode)?.backend {
            Backend::Lower => self.lower.getxattr(ctx, inode, name, size),
            Backend::Upper => self.upper()?.getxattr(ctx, inode, name, size),
        }
    }

    fn listxattr(&self, ctx: Context, inode: Inode, size: u32) -> io::Result<ListxattrReply> {
        match self.route(inode)?.backend {
            Backend::Lower => self.lower.listxattr(ctx, inode, size),
            Backend::Upper => self.upper()?.listxattr(ctx, inode, size),
        }
    }

    fn removexattr(&self, ctx: Context, inode: Inode, name: &CStr) -> io::Result<()> {
        match self.route(inode)?.backend {
            Backend::Lower => self.lower.removexattr(ctx, inode, name),
            Backend::Upper => self.upper()?.removexattr(ctx, inode, name),
        }
    }

    fn opendir(
        &self,
        ctx: Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        match self.route(inode)?.backend {
            Backend::Lower => self.lower.opendir(ctx, inode, flags),
            Backend::Upper => self.upper()?.opendir(ctx, inode, flags),
        }
    }

    fn readdir<F>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        let route = self.route(inode)?;
        if route.backend == Backend::Upper {
            return self
                .upper()?
                .readdir(ctx, inode, handle, size, offset, add_entry);
        }
        if offset & SYNTHETIC_READDIR_OFFSET != 0 {
            return self.add_upper_readdir_entries(ctx, &route.path, offset, |dir_entry, _| {
                add_entry(dir_entry)
            });
        }

        let mut current_offset = offset;
        loop {
            let mut callbacks = 0usize;
            let mut stopped = false;
            let mut last_offset = current_offset;
            self.lower
                .readdir(ctx, inode, handle, size, current_offset, |dir_entry| {
                    callbacks += 1;
                    last_offset = dir_entry.offset;
                    if self.masks.is_direct_child(&route.path, dir_entry.name) {
                        return Ok(1);
                    }
                    let result = add_entry(dir_entry)?;
                    if result == 0 {
                        stopped = true;
                    }
                    Ok(result)
                })?;
            if stopped {
                return Ok(());
            }
            if callbacks == 0 {
                break;
            }
            current_offset = last_offset;
        }

        self.add_upper_readdir_entries(ctx, &route.path, 0, |dir_entry, _| add_entry(dir_entry))
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
        let route = self.route(inode)?;
        if route.backend == Backend::Upper {
            return self
                .upper()?
                .readdirplus(ctx, inode, handle, size, offset, add_entry);
        }
        if offset & SYNTHETIC_READDIR_OFFSET != 0 {
            return self.add_upper_readdir_entries(ctx, &route.path, offset, add_entry);
        }

        let mut current_offset = offset;
        loop {
            let mut callbacks = 0usize;
            let mut stopped = false;
            let mut last_offset = current_offset;
            self.lower
                .readdir(ctx, inode, handle, size, current_offset, |dir_entry| {
                    callbacks += 1;
                    last_offset = dir_entry.offset;
                    if self.masks.is_direct_child(&route.path, dir_entry.name) {
                        return Ok(1);
                    }
                    let name =
                        CString::new(dir_entry.name.to_vec()).map_err(|_| linux_errno::einval())?;
                    let entry = self.lower.lookup(ctx, inode, &name)?;
                    let mut child_path = route.path.clone();
                    child_path.push(dir_entry.name.to_vec());
                    self.record_entry(Backend::Lower, child_path, &entry);
                    let result = add_entry(dir_entry, entry)?;
                    if result == 0 {
                        stopped = true;
                    }
                    Ok(result)
                })?;
            if stopped {
                return Ok(());
            }
            if callbacks == 0 {
                break;
            }
            current_offset = last_offset;
        }

        self.add_upper_readdir_entries(ctx, &route.path, 0, add_entry)
    }

    fn fsyncdir(
        &self,
        ctx: Context,
        inode: Inode,
        datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        match self.route(inode)?.backend {
            Backend::Lower => self.lower.fsyncdir(ctx, inode, datasync, handle),
            Backend::Upper => self.upper()?.fsyncdir(ctx, inode, datasync, handle),
        }
    }

    fn releasedir(&self, ctx: Context, inode: Inode, flags: u32, handle: Handle) -> io::Result<()> {
        match self.route(inode)?.backend {
            Backend::Lower => self.lower.releasedir(ctx, inode, flags, handle),
            Backend::Upper => self.upper()?.releasedir(ctx, inode, flags, handle),
        }
    }

    fn access(&self, ctx: Context, inode: Inode, mask: u32) -> io::Result<()> {
        match self.route(inode)?.backend {
            Backend::Lower => self.lower.access(ctx, inode, mask),
            Backend::Upper => self.upper()?.access(ctx, inode, mask),
        }
    }

    fn lseek(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        match self.route(inode)?.backend {
            Backend::Lower => self.lower.lseek(ctx, inode, handle, offset, whence),
            Backend::Upper => self.upper()?.lseek(ctx, inode, handle, offset, whence),
        }
    }

    fn copyfilerange(
        &self,
        ctx: Context,
        inode_in: Inode,
        handle_in: Handle,
        offset_in: u64,
        inode_out: Inode,
        handle_out: Handle,
        offset_out: u64,
        len: u64,
        flags: u64,
    ) -> io::Result<usize> {
        let input = self.route(inode_in)?;
        let output = self.route(inode_out)?;
        if input.backend != output.backend {
            return Err(linux_errno::exdev());
        }
        match input.backend {
            Backend::Lower => self.lower.copyfilerange(
                ctx, inode_in, handle_in, offset_in, inode_out, handle_out, offset_out, len, flags,
            ),
            Backend::Upper => self.upper()?.copyfilerange(
                ctx, inode_in, handle_in, offset_in, inode_out, handle_out, offset_out, len, flags,
            ),
        }
    }

    fn setupmapping(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        host_shm_base: u64,
        shm_size: u64,
        #[cfg(target_os = "macos")] map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        match self.route(inode)?.backend {
            Backend::Lower => self.lower.setupmapping(
                ctx,
                inode,
                handle,
                foffset,
                len,
                flags,
                moffset,
                host_shm_base,
                shm_size,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
            Backend::Upper => self.upper()?.setupmapping(
                ctx,
                inode,
                handle,
                foffset,
                len,
                flags,
                moffset,
                host_shm_base,
                shm_size,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
        }
    }

    fn removemapping(
        &self,
        ctx: Context,
        requests: Vec<RemovemappingOne>,
        host_shm_base: u64,
        shm_size: u64,
        #[cfg(target_os = "macos")] map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        let result = self.lower.removemapping(
            ctx,
            requests.clone(),
            host_shm_base,
            shm_size,
            #[cfg(target_os = "macos")]
            map_sender,
        );
        if let Some(upper) = &self.upper {
            upper.removemapping(
                ctx,
                requests,
                host_shm_base,
                shm_size,
                #[cfg(target_os = "macos")]
                map_sender,
            )?;
        }
        result
    }

    fn ioctl(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        flags: u32,
        cmd: u32,
        arg: u64,
        in_size: u32,
        out_size: u32,
        exit_code: &Arc<AtomicI32>,
    ) -> io::Result<Vec<u8>> {
        match self.route(inode)?.backend {
            Backend::Lower => self.lower.ioctl(
                ctx, inode, handle, flags, cmd, arg, in_size, out_size, exit_code,
            ),
            Backend::Upper => self.upper()?.ioctl(
                ctx, inode, handle, flags, cmd, arg, in_size, out_size, exit_code,
            ),
        }
    }

    fn getlk(&self) -> io::Result<()> {
        self.lower.getlk()
    }

    fn setlk(&self) -> io::Result<()> {
        self.lower.setlk()
    }

    fn setlkw(&self) -> io::Result<()> {
        self.lower.setlkw()
    }

    fn bmap(&self) -> io::Result<()> {
        self.lower.bmap()
    }

    fn poll(&self) -> io::Result<()> {
        self.lower.poll()
    }

    fn notify_reply(&self) -> io::Result<()> {
        self.lower.notify_reply()
    }
}

impl<L: FileSystem<Inode = Inode, Handle = Handle>> MaskFs<L> {
    fn remove(&self, ctx: Context, parent: Inode, name: &CStr, directory: bool) -> io::Result<()> {
        let parent_route = self.route(parent)?;
        match self.route_child(&parent_route, name) {
            ChildRoute::Lower { .. } => {
                if directory {
                    self.lower.rmdir(ctx, parent, name)
                } else {
                    self.lower.unlink(ctx, parent, name)
                }
            }
            ChildRoute::Upper { path, .. } => {
                let parent = self.upper_parent_inode(ctx, &path[..path.len() - 1])?;
                let result = if directory {
                    self.upper()?.rmdir(ctx, parent, name)
                } else {
                    self.upper()?.unlink(ctx, parent, name)
                };
                if result.is_ok() {
                    self.path_inodes
                        .write()
                        .unwrap()
                        .remove(&(Backend::Upper, path_key(&path)));
                }
                result
            }
        }
    }
}

fn child_backend_path(child: &ChildRoute) -> io::Result<(Backend, Vec<Vec<u8>>)> {
    match child {
        ChildRoute::Lower { path } => Ok((Backend::Lower, path.clone())),
        ChildRoute::Upper { path, .. } => Ok((Backend::Upper, path.clone())),
    }
}

fn path_key(path: &[Vec<u8>]) -> Vec<u8> {
    let mut key = Vec::new();
    for (index, component) in path.iter().enumerate() {
        if index > 0 {
            key.push(b'/');
        }
        key.extend_from_slice(component);
    }
    key
}

fn path_starts_with(path: &[Vec<u8>], prefix: &[Vec<u8>], case_insensitive: bool) -> bool {
    !prefix.is_empty()
        && path.len() >= prefix.len()
        && path.iter().zip(prefix.iter()).all(|(left, right)| {
            if case_insensitive {
                left.eq_ignore_ascii_case(right)
            } else {
                left == right
            }
        })
}

fn storage_path(storage: &str, components: &[Vec<u8>]) -> PathBuf {
    let mut path = PathBuf::from(storage);
    for component in components {
        path.push(OsStr::from_bytes(component));
    }
    path
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    struct TempTree {
        path: PathBuf,
    }

    impl TempTree {
        fn new(name: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "krun-mask-fs-{name}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
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

    #[test]
    fn masked_mounts_do_not_advertise_readdirplus() {
        let source = TempTree::new("source");
        let storage = TempTree::new("storage");

        let inode_alloc = Arc::new(InodeAllocator::new());
        let lower = PassthroughFs::new(
            passthrough::Config {
                root_dir: source.path.to_string_lossy().into_owned(),
                ..Default::default()
            },
            inode_alloc.clone(),
        )
        .unwrap();
        let fs = MaskFs::new(
            lower,
            MaskConfig {
                paths: vec!["/node_modules".to_string()],
                storage: Some(storage.path.to_string_lossy().into_owned()),
            },
            inode_alloc,
            false,
        )
        .unwrap();

        let opts = fs
            .init(FsOptions::DO_READDIRPLUS | FsOptions::READDIRPLUS_AUTO)
            .unwrap();
        assert!(!opts.contains(FsOptions::DO_READDIRPLUS));
        assert!(!opts.contains(FsOptions::READDIRPLUS_AUTO));
    }

    #[test]
    fn writable_masks_hide_lower_lookups_and_create_in_storage() {
        let source = TempTree::new("source");
        let storage = TempTree::new("storage");
        fs::create_dir(source.path.join("node_modules")).unwrap();
        fs::write(source.path.join("node_modules").join("lower.txt"), "lower").unwrap();
        fs::write(source.path.join("visible"), "visible").unwrap();
        fs::write(source.path.join("preexisting"), "lower").unwrap();
        fs::write(storage.path.join("preexisting"), "upper-preexisting").unwrap();

        let inode_alloc = Arc::new(InodeAllocator::new());
        let lower = PassthroughFs::new(
            passthrough::Config {
                root_dir: source.path.to_string_lossy().into_owned(),
                ..Default::default()
            },
            inode_alloc.clone(),
        )
        .unwrap();
        let fs = MaskFs::new(
            lower,
            MaskConfig {
                paths: vec!["/node_modules".to_string(), "/preexisting".to_string()],
                storage: Some(storage.path.to_string_lossy().into_owned()),
            },
            inode_alloc,
            false,
        )
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();

        let ctx = context();
        let (handle, _) = fs
            .opendir(ctx, fuse::ROOT_ID, libc::O_RDONLY as u32)
            .unwrap();
        let handle = handle.expect("passthrough directories use handles");
        let mut names = Vec::new();
        fs.readdirplus(ctx, fuse::ROOT_ID, handle, 4096, 0, |dir_entry, entry| {
            let name = String::from_utf8(dir_entry.name.to_vec()).unwrap();
            if name == "preexisting" {
                assert_eq!(dir_entry.ino, entry.attr.st_ino);
            }
            names.push(name);
            Ok(1)
        })
        .unwrap();
        fs.releasedir(ctx, fuse::ROOT_ID, 0, handle).unwrap();
        assert!(names.contains(&"visible".to_string()));
        assert!(names.contains(&"preexisting".to_string()));
        assert!(!names.contains(&"node_modules".to_string()));

        let preexisting = CString::new("preexisting").unwrap();
        let entry = fs.lookup(ctx, fuse::ROOT_ID, &preexisting).unwrap();
        assert_eq!(entry.attr.st_size, "upper-preexisting".len() as i64);
        assert_eq!(entry.entry_timeout, Duration::ZERO);
        assert_eq!(entry.attr_timeout, Duration::ZERO);

        let node_modules = CString::new("node_modules").unwrap();
        let err = match fs.lookup(ctx, fuse::ROOT_ID, &node_modules) {
            Ok(_) => panic!("masked lower directory was visible"),
            Err(err) => err,
        };
        assert_eq!(err.raw_os_error(), Some(libc::ENOENT));

        let (entry, _, _) = fs
            .create(
                ctx,
                fuse::ROOT_ID,
                &node_modules,
                libc::S_IFREG as u32 | 0o644,
                false,
                libc::O_CREAT as u32 | libc::O_WRONLY as u32,
                0,
                Extensions::default(),
            )
            .unwrap();
        assert_eq!(entry.attr.st_size, 0);
        assert_eq!(entry.entry_timeout, Duration::ZERO);
        assert_eq!(entry.attr_timeout, Duration::ZERO);
        assert!(storage.path.join("node_modules").is_file());
        assert!(source.path.join("node_modules").is_dir());
    }

    #[test]
    fn case_insensitive_masks_route_alternate_casing_to_upper() {
        let source = TempTree::new("source");
        let storage = TempTree::new("storage");
        fs::create_dir(source.path.join(".git")).unwrap();

        let inode_alloc = Arc::new(InodeAllocator::new());
        let lower = PassthroughFs::new(
            passthrough::Config {
                root_dir: source.path.to_string_lossy().into_owned(),
                ..Default::default()
            },
            inode_alloc.clone(),
        )
        .unwrap();
        let fs = MaskFs::new(
            lower,
            MaskConfig {
                paths: vec!["/.git".to_string()],
                storage: Some(storage.path.to_string_lossy().into_owned()),
            },
            inode_alloc,
            true,
        )
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();

        let ctx = context();
        let git = CString::new(".GIT").unwrap();
        let err = match fs.lookup(ctx, fuse::ROOT_ID, &git) {
            Ok(_) => panic!("alternate casing reached the lower masked directory"),
            Err(err) => err,
        };
        assert_eq!(err.raw_os_error(), Some(libc::ENOENT));

        let (entry, _, _) = fs
            .create(
                ctx,
                fuse::ROOT_ID,
                &git,
                libc::S_IFREG as u32 | 0o644,
                false,
                libc::O_CREAT as u32 | libc::O_WRONLY as u32,
                0,
                Extensions::default(),
            )
            .unwrap();
        assert_eq!(entry.attr.st_size, 0);
        assert!(storage.path.join(".GIT").is_file());
        assert!(source.path.join(".git").is_dir());
    }
}

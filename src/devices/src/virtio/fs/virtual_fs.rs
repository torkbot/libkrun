use std::ffi::CStr;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use super::bindings;
use super::filesystem::{
    Context, DirEntry, Entry, FileSystem, FsOptions, GetxattrReply, ListxattrReply, OpenOptions,
    SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualDirEntry {
    pub inode: u64,
    pub type_: u32,
    pub name: Vec<u8>,
}

pub trait VirtualFsBackend: Send + Sync + 'static {
    fn lookup(&self, parent: u64, name: &CStr) -> io::Result<Entry>;

    fn getattr(&self, inode: u64) -> io::Result<(bindings::stat64, Duration)>;

    fn readdir(&self, inode: u64) -> io::Result<Vec<VirtualDirEntry>>;

    fn read(&self, inode: u64, offset: u64, size: u32) -> io::Result<Vec<u8>>;

    fn create(&self, parent: u64, name: &CStr, mode: u32) -> io::Result<Entry> {
        let _ = (parent, name, mode);
        Err(io::Error::from_raw_os_error(bindings::LINUX_ENOSYS))
    }

    fn write(&self, inode: u64, offset: u64, data: &[u8]) -> io::Result<usize> {
        let _ = (inode, offset, data);
        Err(io::Error::from_raw_os_error(bindings::LINUX_ENOSYS))
    }

    fn truncate(&self, inode: u64, size: u64) -> io::Result<(bindings::stat64, Duration)> {
        let _ = (inode, size);
        Err(io::Error::from_raw_os_error(bindings::LINUX_ENOSYS))
    }

    fn mkdir(&self, parent: u64, name: &CStr, mode: u32) -> io::Result<Entry> {
        let _ = (parent, name, mode);
        Err(io::Error::from_raw_os_error(bindings::LINUX_ENOSYS))
    }

    fn unlink(&self, parent: u64, name: &CStr) -> io::Result<()> {
        let _ = (parent, name);
        Err(io::Error::from_raw_os_error(bindings::LINUX_ENOSYS))
    }

    fn rmdir(&self, parent: u64, name: &CStr) -> io::Result<()> {
        let _ = (parent, name);
        Err(io::Error::from_raw_os_error(bindings::LINUX_ENOSYS))
    }

    fn rename(
        &self,
        olddir: u64,
        oldname: &CStr,
        newdir: u64,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        let _ = (olddir, oldname, newdir, newname, flags);
        Err(io::Error::from_raw_os_error(bindings::LINUX_ENOSYS))
    }

    fn link(&self, inode: u64, newparent: u64, newname: &CStr) -> io::Result<Entry> {
        let _ = (inode, newparent, newname);
        Err(io::Error::from_raw_os_error(bindings::LINUX_ENOSYS))
    }

    fn symlink(&self, linkname: &CStr, parent: u64, name: &CStr) -> io::Result<Entry> {
        let _ = (linkname, parent, name);
        Err(io::Error::from_raw_os_error(bindings::LINUX_ENOSYS))
    }

    fn readlink(&self, inode: u64) -> io::Result<Vec<u8>> {
        let _ = inode;
        Err(io::Error::from_raw_os_error(bindings::LINUX_ENOSYS))
    }

    fn setxattr(&self, inode: u64, name: &CStr, value: &[u8], flags: u32) -> io::Result<()> {
        let _ = (inode, name, value, flags);
        Err(io::Error::from_raw_os_error(bindings::LINUX_ENOSYS))
    }

    fn getxattr(&self, inode: u64, name: &CStr, size: u32) -> io::Result<GetxattrReply> {
        let _ = (inode, name, size);
        Err(io::Error::from_raw_os_error(bindings::LINUX_ENOSYS))
    }

    fn listxattr(&self, inode: u64, size: u32) -> io::Result<ListxattrReply> {
        let _ = (inode, size);
        Err(io::Error::from_raw_os_error(bindings::LINUX_ENOSYS))
    }

    fn removexattr(&self, inode: u64, name: &CStr) -> io::Result<()> {
        let _ = (inode, name);
        Err(io::Error::from_raw_os_error(bindings::LINUX_ENOSYS))
    }
}

#[derive(Clone)]
pub struct VirtualFs {
    backend: Arc<dyn VirtualFsBackend>,
}

impl VirtualFs {
    pub fn new(backend: Arc<dyn VirtualFsBackend>) -> Self {
        Self { backend }
    }
}

impl FileSystem for VirtualFs {
    type Inode = u64;
    type Handle = u64;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        Ok(capable & FsOptions::empty())
    }

    fn lookup(&self, _ctx: Context, parent: Self::Inode, name: &CStr) -> io::Result<Entry> {
        self.backend.lookup(parent, name)
    }

    fn getattr(
        &self,
        _ctx: Context,
        inode: Self::Inode,
        _handle: Option<Self::Handle>,
    ) -> io::Result<(bindings::stat64, Duration)> {
        self.backend.getattr(inode)
    }

    fn open(
        &self,
        _ctx: Context,
        inode: Self::Inode,
        _kill_priv: bool,
        _flags: u32,
    ) -> io::Result<(Option<Self::Handle>, OpenOptions)> {
        Ok((Some(inode), OpenOptions::empty()))
    }

    fn setattr(
        &self,
        _ctx: Context,
        inode: Self::Inode,
        attr: bindings::stat64,
        _handle: Option<Self::Handle>,
        valid: SetattrValid,
    ) -> io::Result<(bindings::stat64, Duration)> {
        if valid.contains(SetattrValid::SIZE) {
            return self.backend.truncate(inode, attr.st_size as u64);
        }

        self.backend.getattr(inode)
    }

    fn create(
        &self,
        _ctx: Context,
        parent: Self::Inode,
        name: &CStr,
        mode: u32,
        _kill_priv: bool,
        _flags: u32,
        _umask: u32,
        _extensions: super::filesystem::Extensions,
    ) -> io::Result<(Entry, Option<Self::Handle>, OpenOptions)> {
        let entry = self.backend.create(parent, name, mode)?;
        let inode = entry.inode;
        Ok((entry, Some(inode), OpenOptions::empty()))
    }

    fn mknod(
        &self,
        _ctx: Context,
        parent: Self::Inode,
        name: &CStr,
        mode: u32,
        _rdev: u32,
        _umask: u32,
        _extensions: super::filesystem::Extensions,
    ) -> io::Result<Entry> {
        self.backend.create(parent, name, mode)
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        _ctx: Context,
        inode: Self::Inode,
        _handle: Self::Handle,
        mut w: W,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        let data = self.backend.read(inode, offset, size)?;
        w.write_all(&data)?;
        Ok(data.len())
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        _ctx: Context,
        inode: Self::Inode,
        _handle: Self::Handle,
        mut r: R,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        _kill_priv: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        let mut data = vec![0; size as usize];
        r.read_exact(&mut data)?;
        self.backend.write(inode, offset, &data)
    }

    fn release(
        &self,
        _ctx: Context,
        _inode: Self::Inode,
        _flags: u32,
        _handle: Self::Handle,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        Ok(())
    }

    fn opendir(
        &self,
        _ctx: Context,
        inode: Self::Inode,
        _flags: u32,
    ) -> io::Result<(Option<Self::Handle>, OpenOptions)> {
        Ok((Some(inode), OpenOptions::empty()))
    }

    fn readdir<F>(
        &self,
        _ctx: Context,
        inode: Self::Inode,
        _handle: Self::Handle,
        _size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        for (index, entry) in self.backend.readdir(inode)?.iter().enumerate() {
            let next_offset = (index + 1) as u64;
            if next_offset <= offset {
                continue;
            }

            add_entry(DirEntry {
                ino: entry.inode,
                offset: next_offset,
                type_: entry.type_,
                name: &entry.name,
            })?;
        }

        Ok(())
    }

    fn releasedir(
        &self,
        _ctx: Context,
        _inode: Self::Inode,
        _flags: u32,
        _handle: Self::Handle,
    ) -> io::Result<()> {
        Ok(())
    }

    fn access(&self, _ctx: Context, _inode: Self::Inode, _mask: u32) -> io::Result<()> {
        Ok(())
    }

    fn mkdir(
        &self,
        _ctx: Context,
        parent: Self::Inode,
        name: &CStr,
        mode: u32,
        _umask: u32,
        _extensions: super::filesystem::Extensions,
    ) -> io::Result<Entry> {
        self.backend.mkdir(parent, name, mode)
    }

    fn unlink(&self, _ctx: Context, parent: Self::Inode, name: &CStr) -> io::Result<()> {
        self.backend.unlink(parent, name)
    }

    fn rmdir(&self, _ctx: Context, parent: Self::Inode, name: &CStr) -> io::Result<()> {
        self.backend.rmdir(parent, name)
    }

    fn rename(
        &self,
        _ctx: Context,
        olddir: Self::Inode,
        oldname: &CStr,
        newdir: Self::Inode,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        self.backend.rename(olddir, oldname, newdir, newname, flags)
    }

    fn link(
        &self,
        _ctx: Context,
        inode: Self::Inode,
        newparent: Self::Inode,
        newname: &CStr,
    ) -> io::Result<Entry> {
        self.backend.link(inode, newparent, newname)
    }

    fn symlink(
        &self,
        _ctx: Context,
        linkname: &CStr,
        parent: Self::Inode,
        name: &CStr,
        _extensions: super::filesystem::Extensions,
    ) -> io::Result<Entry> {
        self.backend.symlink(linkname, parent, name)
    }

    fn readlink(&self, _ctx: Context, inode: Self::Inode) -> io::Result<Vec<u8>> {
        self.backend.readlink(inode)
    }

    fn setxattr(
        &self,
        _ctx: Context,
        inode: Self::Inode,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        self.backend.setxattr(inode, name, value, flags)
    }

    fn getxattr(
        &self,
        _ctx: Context,
        inode: Self::Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        self.backend.getxattr(inode, name, size)
    }

    fn listxattr(
        &self,
        _ctx: Context,
        inode: Self::Inode,
        size: u32,
    ) -> io::Result<ListxattrReply> {
        self.backend.listxattr(inode, size)
    }

    fn removexattr(&self, _ctx: Context, inode: Self::Inode, name: &CStr) -> io::Result<()> {
        self.backend.removexattr(inode, name)
    }
}

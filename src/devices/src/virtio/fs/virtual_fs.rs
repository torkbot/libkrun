use std::ffi::CStr;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use super::bindings;
use super::filesystem::{
    Context, DirEntry, Entry, FileSystem, FsOptions, OpenOptions, ZeroCopyWriter,
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
        Ok(capable & FsOptions::DO_READDIRPLUS)
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
}

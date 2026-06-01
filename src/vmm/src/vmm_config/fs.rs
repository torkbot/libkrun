use std::fmt;
use std::sync::Arc;

use devices::virtio::fs::virtual_entry::VirtualDirEntry;
use devices::virtio::fs::VirtualFsBackend;

#[derive(Clone)]
pub struct FsDeviceConfig {
    pub fs_id: String,
    pub backend: FsDeviceBackend,
    pub shm_size: Option<usize>,
}

#[derive(Clone)]
pub enum FsDeviceBackend {
    Passthrough {
        shared_dir: String,
        read_only: bool,
        virtual_entries: Vec<VirtualDirEntry>,
    },
    Null {
        virtual_entries: Vec<VirtualDirEntry>,
    },
    Virtual {
        backend: Arc<dyn VirtualFsBackend>,
    },
}

impl fmt::Debug for FsDeviceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FsDeviceConfig")
            .field("fs_id", &self.fs_id)
            .field("backend", &self.backend)
            .field("shm_size", &self.shm_size)
            .finish()
    }
}

impl fmt::Debug for FsDeviceBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsDeviceBackend::Passthrough {
                shared_dir,
                read_only,
                virtual_entries,
            } => f
                .debug_struct("Passthrough")
                .field("shared_dir", shared_dir)
                .field("read_only", read_only)
                .field("virtual_entries", virtual_entries)
                .finish(),
            FsDeviceBackend::Null { virtual_entries } => f
                .debug_struct("Null")
                .field("virtual_entries", virtual_entries)
                .finish(),
            FsDeviceBackend::Virtual { .. } => f.write_str("Virtual"),
        }
    }
}

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};

use devices::virtio::{
    Block, CacheType,
    block::{ImageType, SyncMode},
};
use imago::{DynStorage, SyncFormatAccess};

#[derive(Debug)]
pub enum BlockConfigError {
    /// Failed to create the block device.
    CreateBlockDevice(std::io::Error),
}

impl fmt::Display for BlockConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::BlockConfigError::*;
        match *self {
            CreateBlockDevice(ref e) => write!(f, "Cannot create block device: {e:?}"),
        }
    }
}

type Result<T> = std::result::Result<T, BlockConfigError>;

#[derive(Clone)]
pub struct BlockDeviceConfig {
    pub block_id: String,
    pub cache_type: CacheType,
    pub source: BlockDeviceSource,
    pub is_disk_read_only: bool,
    pub direct_io: bool,
    pub sync_mode: SyncMode,
}

#[derive(Clone)]
pub enum BlockDeviceSource {
    Path {
        disk_image_path: String,
        disk_image_format: ImageType,
    },
    Storage {
        disk_image: Arc<Mutex<SyncFormatAccess<Box<dyn DynStorage>>>>,
    },
}

impl fmt::Debug for BlockDeviceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockDeviceConfig")
            .field("block_id", &self.block_id)
            .field("cache_type", &self.cache_type)
            .field("source", &self.source)
            .field("is_disk_read_only", &self.is_disk_read_only)
            .field("direct_io", &self.direct_io)
            .field("sync_mode", &self.sync_mode)
            .finish()
    }
}

impl fmt::Debug for BlockDeviceSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path {
                disk_image_path,
                disk_image_format,
            } => f
                .debug_struct("Path")
                .field("disk_image_path", disk_image_path)
                .field("disk_image_format", disk_image_format)
                .finish(),
            Self::Storage { .. } => f.write_str("Storage { .. }"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockRootConfig {
    pub device: String,
    pub fstype: Option<String>,
    pub options: Option<String>,
}

#[derive(Default)]
pub struct BlockBuilder {
    pub list: VecDeque<Arc<Mutex<Block>>>,
}

impl BlockBuilder {
    pub fn new() -> Self {
        Self {
            list: VecDeque::<Arc<Mutex<Block>>>::new(),
        }
    }

    pub fn insert(&mut self, config: BlockDeviceConfig) -> Result<()> {
        let block_dev = Arc::new(Mutex::new(Self::create_block(config)?));
        self.list.push_back(block_dev);
        Ok(())
    }

    pub fn create_block(config: BlockDeviceConfig) -> Result<Block> {
        match config.source {
            BlockDeviceSource::Path {
                disk_image_path,
                disk_image_format,
            } => devices::virtio::Block::new(
                config.block_id,
                None,
                config.cache_type,
                disk_image_path,
                disk_image_format,
                config.is_disk_read_only,
                config.direct_io,
                config.sync_mode,
            )
            .map_err(BlockConfigError::CreateBlockDevice),
            BlockDeviceSource::Storage { disk_image } => devices::virtio::Block::new_with_storage(
                config.block_id,
                None,
                config.cache_type,
                disk_image,
                config.is_disk_read_only,
                config.sync_mode,
            )
            .map_err(BlockConfigError::CreateBlockDevice),
        }
    }
}

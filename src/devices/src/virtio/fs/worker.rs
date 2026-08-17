#[cfg(target_os = "macos")]
use crossbeam_channel::Sender;
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;

#[cfg(target_os = "macos")]
use std::ffi::CString;
use std::io;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::AtomicI32;
use std::thread;
use std::time::Duration;
#[cfg(windows)]
use utils::windows::AsRawFd;

use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

use super::super::{FsError, Queue};
use super::augment_fs::AugmentFs;
use super::defs::{HPQ_INDEX, REQ_INDEX};
use super::descriptor_utils::{Reader, Writer};
use super::inode_alloc::InodeAllocator;
use super::mask_fs::{MaskConfig, MaskFs};
use super::null_fs::NullFs;
use super::passthrough::{self, PassthroughFs};
use super::read_only::PassthroughFsRo;
use super::server::Server;
use super::virtual_entry::VirtualDirEntry;
use super::virtual_fs::VirtualFs;
use crate::virtio::{InterruptTransport, VirtioShmRegion};

pub enum FsBackend {
    Passthrough {
        config: passthrough::Config,
        read_only: bool,
        virtual_entries: Vec<VirtualDirEntry>,
        mask: Option<MaskConfig>,
    },
    Null {
        virtual_entries: Vec<VirtualDirEntry>,
    },
    Virtual(VirtualFs),
}

enum FsServer {
    ReadWrite(Server<AugmentFs<PassthroughFs>>),
    ReadOnly(Server<AugmentFs<PassthroughFsRo>>),
    MaskedReadWrite(Server<AugmentFs<MaskFs<PassthroughFs>>>),
    MaskedReadOnly(Server<AugmentFs<MaskFs<PassthroughFsRo>>>),
    Null(Server<AugmentFs<NullFs>>),
    Virtual(Server<VirtualFs>),
}

impl FsServer {
    fn handle_message(
        &self,
        r: Reader,
        w: Writer,
        allow_idmap: bool,
        shm_region: &Option<VirtioShmRegion>,
        exit_code: &Arc<AtomicI32>,
        #[cfg(target_os = "macos")] map_sender: &Option<Sender<WorkerMessage>>,
    ) -> super::Result<usize> {
        match self {
            FsServer::ReadWrite(s) => s.handle_message(
                r,
                w,
                allow_idmap,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
            FsServer::ReadOnly(s) => s.handle_message(
                r,
                w,
                allow_idmap,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
            FsServer::MaskedReadWrite(s) => s.handle_message(
                r,
                w,
                allow_idmap,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
            FsServer::MaskedReadOnly(s) => s.handle_message(
                r,
                w,
                allow_idmap,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
            FsServer::Virtual(s) => s.handle_message(
                r,
                w,
                allow_idmap,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
            FsServer::Null(s) => s.handle_message(
                r,
                w,
                allow_idmap,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
        }
    }
}

pub struct FsWorker {
    queues: Vec<Queue>,
    queue_evts: Vec<Arc<EventFd>>,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    allow_idmap: bool,
    shm_region: Option<VirtioShmRegion>,
    server: FsServer,
    stop_fd: EventFd,
    exit_code: Arc<AtomicI32>,
    #[cfg(target_os = "macos")]
    map_sender: Option<Sender<WorkerMessage>>,
}

impl FsWorker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        queues: Vec<Queue>,
        queue_evts: Vec<Arc<EventFd>>,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        allow_idmap: bool,
        shm_region: Option<VirtioShmRegion>,
        backend: FsBackend,
        stop_fd: EventFd,
        exit_code: Arc<AtomicI32>,
        #[cfg(target_os = "macos")] map_sender: Option<Sender<WorkerMessage>>,
    ) -> Result<Self, io::Error> {
        let inode_alloc = Arc::new(InodeAllocator::new());
        let server = match backend {
            FsBackend::Passthrough {
                config,
                read_only: true,
                virtual_entries,
                mask: None,
            } => {
                let inner = PassthroughFsRo::new(config, inode_alloc.clone())?;
                FsServer::ReadOnly(Server::new(AugmentFs::new(
                    inner,
                    &inode_alloc,
                    virtual_entries,
                )))
            }
            FsBackend::Passthrough {
                config,
                read_only: true,
                virtual_entries,
                mask: Some(mask),
            } => {
                let case_insensitive = host_path_is_case_insensitive(&config.root_dir)?;
                let upper_semantics = config.semantics;
                let config = uncached_masked_passthrough_config(config);
                let lower = PassthroughFsRo::new(config, inode_alloc.clone())?;
                let inner = MaskFs::new(
                    lower,
                    mask,
                    upper_semantics,
                    inode_alloc.clone(),
                    case_insensitive,
                )?;
                FsServer::MaskedReadOnly(Server::new(AugmentFs::new(
                    inner,
                    &inode_alloc,
                    virtual_entries,
                )))
            }
            FsBackend::Passthrough {
                config,
                virtual_entries,
                mask: None,
                ..
            } => {
                let inner = PassthroughFs::new(config, inode_alloc.clone())?;
                FsServer::ReadWrite(Server::new(AugmentFs::new(
                    inner,
                    &inode_alloc,
                    virtual_entries,
                )))
            }
            FsBackend::Passthrough {
                config,
                virtual_entries,
                mask: Some(mask),
                ..
            } => {
                let case_insensitive = host_path_is_case_insensitive(&config.root_dir)?;
                let upper_semantics = config.semantics;
                let config = uncached_masked_passthrough_config(config);
                let lower = PassthroughFs::new(config, inode_alloc.clone())?;
                let inner = MaskFs::new(
                    lower,
                    mask,
                    upper_semantics,
                    inode_alloc.clone(),
                    case_insensitive,
                )?;
                FsServer::MaskedReadWrite(Server::new(AugmentFs::new(
                    inner,
                    &inode_alloc,
                    virtual_entries,
                )))
            }
            FsBackend::Null { virtual_entries } => FsServer::Null(Server::new(AugmentFs::new(
                NullFs,
                &inode_alloc,
                virtual_entries,
            ))),
            FsBackend::Virtual(fs) => FsServer::Virtual(Server::new(fs)),
        };
        Ok(Self {
            queues,
            queue_evts,
            interrupt,
            mem,
            allow_idmap,
            shm_region,
            server,
            stop_fd,
            exit_code,
            #[cfg(target_os = "macos")]
            map_sender,
        })
    }

    pub fn run(self) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name("fs worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    fn work(mut self) {
        let virtq_hpq_ev_fd = self.queue_evts[HPQ_INDEX].as_raw_fd();
        let virtq_req_ev_fd = self.queue_evts[REQ_INDEX].as_raw_fd();
        let stop_ev_fd = self.stop_fd.as_raw_fd();

        let mut epoll = Epoll::new().unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_hpq_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_hpq_ev_fd as u64),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_req_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_req_ev_fd as u64),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            stop_ev_fd,
            &EpollEvent::new(EventSet::IN, stop_ev_fd as u64),
        );

        let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        loop {
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();
                        match event_set {
                            EventSet::IN if source == virtq_hpq_ev_fd => {
                                self.handle_event(HPQ_INDEX);
                            }
                            EventSet::IN if source == virtq_req_ev_fd => {
                                self.handle_event(REQ_INDEX);
                            }
                            EventSet::IN if source == stop_ev_fd => {
                                debug!("stopping worker thread");
                                let _ = self.stop_fd.read();
                                return;
                            }
                            _ => {
                                log::warn!(
                                    "Received unknown event: {event_set:?} from fd: {source:?}"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("failed to consume muxer epoll event: {e}");
                }
            }
        }
    }

    fn handle_event(&mut self, queue_index: usize) {
        debug!("Fs: queue event: {queue_index}");
        if let Err(e) = self.queue_evts[queue_index].read() {
            error!("Failed to get queue event: {e:?}");
        }

        loop {
            self.queues[queue_index]
                .disable_notification(&self.mem)
                .unwrap();

            self.process_queue(queue_index);

            if !self.queues[queue_index]
                .enable_notification(&self.mem)
                .unwrap()
            {
                break;
            }
        }
    }

    fn process_queue(&mut self, queue_index: usize) {
        let queue = &mut self.queues[queue_index];
        while let Some(head) = queue.pop(&self.mem) {
            let reader = Reader::new(&self.mem, head.clone())
                .map_err(FsError::QueueReader)
                .unwrap();
            let writer = Writer::new(&self.mem, head.clone())
                .map_err(FsError::QueueWriter)
                .unwrap();

            let len = match self.server.handle_message(
                reader,
                writer,
                self.allow_idmap,
                &self.shm_region,
                &self.exit_code,
                #[cfg(target_os = "macos")]
                &self.map_sender,
            ) {
                Ok(len) => len,
                Err(e) => {
                    error!("error handling message: {e:?}");
                    0
                }
            };

            if let Err(e) = queue.add_used(&self.mem, head.index, len as u32) {
                error!("failed to add used elements to the queue: {e:?}");
            }

            if queue.needs_notification(&self.mem).unwrap() {
                self.interrupt.signal_used_queue();
            }
        }
    }
}

fn uncached_masked_passthrough_config(mut config: passthrough::Config) -> passthrough::Config {
    // A masked mount can intentionally answer a parent/name lookup from upper
    // storage even when a lower child exists. Passthrough dentry caching can
    // otherwise let the guest reuse the lower child across later operations.
    config.entry_timeout = Duration::ZERO;
    config.attr_timeout = Duration::ZERO;
    config
}

#[cfg(target_os = "macos")]
fn host_path_is_case_insensitive(path: &str) -> io::Result<bool> {
    let path = CString::new(path).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let result = unsafe { libc::pathconf(path.as_ptr(), libc::_PC_CASE_SENSITIVE) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result == 0)
}

#[cfg(not(target_os = "macos"))]
fn host_path_is_case_insensitive(_path: &str) -> io::Result<bool> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masked_passthrough_config_disables_entry_and_attr_caches() {
        let config = uncached_masked_passthrough_config(passthrough::Config {
            root_dir: "/mask-lower".to_string(),
            ..Default::default()
        });

        assert_eq!(config.root_dir, "/mask-lower");
        assert_eq!(config.entry_timeout, Duration::ZERO);
        assert_eq!(config.attr_timeout, Duration::ZERO);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_macos_hosts_use_case_sensitive_mask_matching() {
        assert!(!host_path_is_case_insensitive("/unused").unwrap());
    }
}

use crate::{
    crypto::EncryptionManager, error::VpnError, network::tcp_server::TcpServer,
    protocol::ProtocolHandler, vpn::vpn_worker::VpnWorker,
};
use std::collections::HashMap;
use std::sync::{atomic::AtomicBool, Arc, Mutex};
use std::time::Duration;
use std::{thread, vec};

pub struct VpnService {
    server: Arc<Mutex<TcpServer>>,
    routes: Arc<Mutex<HashMap<String, Vec<RouteEntry>>>>,
    protocol_handler: Arc<Mutex<ProtocolHandler>>,
    server_config: Arc<Mutex<VpnConfig>>,
    client_configs: Arc<Mutex<HashMap<String, VpnConfig>>>,

    keep_alive_thread: Option<thread::JoinHandle<()>>,
    worker_threads: Vec<thread::JoinHandle<()>>,
    shutdown_flag: Arc<AtomicBool>,
}

#[derive(Clone, Debug)]
pub struct VpnConfig {
    pub mtu: usize,
    pub keepalive_interval: Duration,
    pub reconnect_attempts: u32,
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            mtu: 1500,
            keepalive_interval: Duration::from_secs(30),
            reconnect_attempts: 3,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub target_network: [u8; 4],
    pub network_mask: [u8; 4],
    pub next_hop: [u8; 4],
    pub metric: u32,
}

impl VpnService {
    pub fn new(
        bind_addr: &str,
        encryption_key: [u8; 32],
        config: Option<VpnConfig>,
    ) -> Result<Self, VpnError> {
        // Initialize TCP server
        let server = Arc::new(Mutex::new(TcpServer::new(bind_addr)?));

        // Initialize encryption and protocol handler
        let encryption = EncryptionManager::new(&encryption_key);
        let protocol_handler = Arc::new(Mutex::new(ProtocolHandler::new(encryption)));

        // Initialize shared data structures
        let routes = Arc::new(Mutex::new(HashMap::new()));
        let client_configs = Arc::new(Mutex::new(HashMap::new()));

        // Use provided config or default
        let server_config = Arc::new(Mutex::new(config.unwrap_or_default()));

        let shutdown_flag = Arc::new(AtomicBool::new(false));

        Ok(Self {
            server,
            protocol_handler,
            routes,
            client_configs,
            server_config,
            keep_alive_thread: None,
            worker_threads: vec![],
            shutdown_flag,
        })
    }

    pub fn start(&mut self) -> Result<(), VpnError> {
        // Start accepting connections
        self.server
            .lock()
            .expect("Unable to access server")
            .start_accept_loop()?;

        // Start keepalive monitoring
        let keepalive_interval = self
            .server_config
            .lock()
            .expect("Config in use")
            .keepalive_interval;
        let server = self.server.clone();
        let shutdown_flag = Arc::clone(&self.shutdown_flag);
        self.keep_alive_thread = Some(thread::spawn(move || {
            while !shutdown_flag.load(std::sync::atomic::Ordering::Relaxed) {
                {
                    Self::check_client_keepalive(&server.lock().expect("Server in use"));
                }
                thread::sleep(keepalive_interval);
            }
        }));

        self.spawn_worker();

        Ok(())
    }

    fn spawn_worker(&mut self) {
        let server = self.server.clone();
        let routes = self.routes.clone();
        let client_configs = self.client_configs.clone();
        let protocol_handler = self.protocol_handler.clone();
        let shutdown_flag = self.shutdown_flag.clone();

        self.worker_threads.push(thread::spawn(move || {
            let worker = VpnWorker::new(
                server,
                routes,
                protocol_handler,
                client_configs,
                shutdown_flag,
            );

            let _ = match worker {
                Ok(w) => w.main_loop(),
                Err(e) => {
                    eprintln!("Worker error: {:?}", e);
                    Ok(())
                }
            };

            println!("Worker thread exiting")
        }));
    }

    pub fn shutdown(&mut self) -> Result<(), VpnError> {
        self.shutdown_flag
            .store(true, std::sync::atomic::Ordering::Relaxed);
        // Shutdown main thread
        for t in std::mem::take(&mut self.worker_threads) {
            t.join().unwrap();
        }

        // Shutdown keepalive thread
        let res1 = match self.keep_alive_thread.take().ok_or(VpnError::GenericError(
            "Shutdown failed to keep alive thread".to_string(),
        )) {
            Ok(handle) => {
                handle
                    .join()
                    .map_err(|e| VpnError::GenericError(format!("Join error: {:?}", e)))?;
                Ok(())
            }
            Err(e) => Err(e),
        };

        // Shutdown server
        let res2 = self
            .server
            .lock()
            .expect("Unable to access server")
            .server_shutdown();

        // Combine results
        res1.and(res2)
    }

    fn check_client_keepalive(server: &TcpServer) {
        let stale_clients = server.get_stale_clients();
        for client_id in stale_clients {
            println!("Removing stale client: {}", client_id);
            server.remove_client(&client_id);
        }
    }
}

impl VpnConfig {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VpnError> {
        if bytes.len() < 12 {
            return Err(VpnError::Protocol("Config data too short".into()));
        }

        let mut mtu_bytes = [0u8; 4];
        let mut keepalive_bytes = [0u8; 4];
        let mut reconnect_bytes = [0u8; 4];

        mtu_bytes.copy_from_slice(&bytes[0..4]);
        keepalive_bytes.copy_from_slice(&bytes[4..8]);
        reconnect_bytes.copy_from_slice(&bytes[8..12]);

        Ok(Self {
            mtu: u32::from_be_bytes(mtu_bytes) as usize,
            keepalive_interval: Duration::from_secs(u32::from_be_bytes(keepalive_bytes) as u64),
            reconnect_attempts: u32::from_be_bytes(reconnect_bytes),
        })
    }
}

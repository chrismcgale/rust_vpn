use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{atomic::AtomicBool, atomic::Ordering, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use crate::error::VpnError;

#[derive(Debug)]
pub struct ClientInfo {
    stream: TcpStream,
    last_seen: Instant,
}

pub struct TcpServer {
    listener: TcpListener,
    clients: Arc<Mutex<HashMap<String, ClientInfo>>>,
    bind_addr: SocketAddr,
    listener_thread: Option<thread::JoinHandle<()>>,
    shutdown_flag: Arc<AtomicBool>,
}

impl Clone for TcpServer {
    fn clone(&self) -> Self {
        Self {
            listener: self.listener.try_clone().unwrap(),
            clients: Arc::clone(&self.clients),
            bind_addr: self.bind_addr,
            listener_thread: None,
            shutdown_flag: self.shutdown_flag.clone(),
        }
    }
}

impl TcpServer {
    pub fn new(bind_addr: &str) -> Result<Self, VpnError> {
        let addr = bind_addr
            .parse()
            .map_err(|e| VpnError::Protocol(format!("Invalid address: {}", e)))?;

        let listener = match std::net::TcpListener::bind(addr) {
            Ok(l) => {
                println!("listening on {}", addr);
                l
            }
            Err(e) => {
                eprintln!("Server: Bind failed: {}", e);
                return Err(VpnError::Io(e));
            }
        };
        listener.set_nonblocking(true)?;

        Ok(Self {
            listener,
            clients: Arc::new(Mutex::new(HashMap::new())),
            bind_addr: addr,
            listener_thread: None,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    pub fn start_accept_loop(&mut self) -> Result<(), VpnError> {
        let clients = Arc::clone(&self.clients);
        let listener = self.listener.try_clone()?;
        let _ = listener.set_nonblocking(true);

        let shutdown_flag = self.shutdown_flag.clone();

        self.listener_thread = Some(thread::spawn(move || {
            while !shutdown_flag.load(std::sync::atomic::Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, addr)) => {
                        let client_id = addr.to_string();

                        if let Err(e) = stream.set_nodelay(true) {
                            eprintln!("Failed to set TCP_NODELAY: {}", e);
                        }

                        let client_info = ClientInfo {
                            stream,
                            last_seen: Instant::now(),
                        };
                        clients.lock().unwrap().insert(client_id, client_info);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => {
                        eprintln!("Accept error: {}", e);
                    }
                }
            }
        }));

        Ok(())
    }

    pub fn server_shutdown(&mut self) -> Result<(), VpnError> {
        println!("server shut");
        self.shutdown_flag.store(true, Ordering::Release);
        match self.listener_thread.take().ok_or(VpnError::GenericError(
            "Shutdown failed to find listener thread".to_string(),
        )) {
            Ok(handle) => {
                handle
                    .join()
                    .map_err(|e| VpnError::GenericError(format!("Join error: {:?}", e)))?;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn service_read_packet(&self, client_id: &str) -> Result<Vec<u8>, VpnError> {
        let mut clients = self.clients.lock().unwrap();
        let client_info = clients.get_mut(client_id).ok_or(VpnError::ClientNotFound)?;

        let _ = client_info.stream.set_nonblocking(true);

        let mut buf = [0; 10];
        match client_info.stream.peek(&mut buf) {
            Ok(size) => {
                if size < 4 {
                    return Ok(vec![]);
                }
            }
            Err(_e) => {
                return Ok(vec![]);
            }
        }

        let mut len_bytes = [0u8; 4];
        client_info.stream.read_exact(&mut len_bytes)?;
        let packet_len = u32::from_be_bytes(len_bytes) as usize;

        if packet_len > 65535 {
            return Err(VpnError::Protocol("Packet too large".into()));
        }

        let mut buffer = vec![0u8; packet_len];
        client_info.stream.read_exact(&mut buffer)?;

        // Update last seen timestamp
        client_info.last_seen = Instant::now();

        Ok(buffer)
    }

    pub fn write_packet(&self, client_id: &str, packet: &[u8]) -> Result<(), VpnError> {
        let mut clients = self.clients.lock().unwrap();
        let client_info = clients.get_mut(client_id).ok_or(VpnError::ClientNotFound)?;

        let len_bytes = (packet.len() as u32).to_be_bytes();
        client_info.stream.write_all(&len_bytes)?;
        client_info.stream.write_all(packet)?;
        client_info.stream.flush()?;

        Ok(())
    }

    pub fn remove_client(&self, client_id: &str) {
        let mut clients = self.clients.lock().unwrap();
        clients.remove(client_id);
    }

    pub fn get_client_ids(&self) -> Vec<String> {
        let clients = self.clients.lock().unwrap();
        clients.keys().cloned().collect()
    }

    pub fn update_client_timestamp(&self, client_id: &str) -> Result<(), VpnError> {
        let mut clients = self.clients.lock().unwrap();
        if let Some(client_info) = clients.get_mut(client_id) {
            client_info.last_seen = Instant::now();
            Ok(())
        } else {
            Err(VpnError::ClientNotFound)
        }
    }

    pub fn get_stale_clients(&self) -> Vec<String> {
        let clients = self.clients.lock().unwrap();
        let timeout = Duration::from_secs(90); // 1 minute timeout

        clients
            .iter()
            .filter(|(_, info)| info.last_seen.elapsed() > timeout)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

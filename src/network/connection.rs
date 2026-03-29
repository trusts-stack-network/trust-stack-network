use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct Connection {
    id: u64,
    stream: Arc<Mutex<TcpStream>>,
    is_active: bool,
}

impl Connection {
    pub fn new(id: u64, stream: TcpStream) -> Self {
        Self {
            id,
            stream: Arc::new(Mutex::new(stream)),
            is_active: true,
        }
    }

    pub fn send(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut stream = self.stream.lock().unwrap();
        stream.write(data)
    }

    pub fn receive(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut stream = self.stream.lock().unwrap();
        stream.read(buf)
    }

    pub fn close(&mut self) -> std::io::Result<()> {
        self.is_active = false;
        let mut stream = self.stream.lock().unwrap();
        stream.shutdown(std::net::Shutdown::Both)
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn is_active(&self) -> bool {
        self.is_active
    }
}

pub struct ConnectionPool {
    connections: Vec<Connection>,
    next_id: u64,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            connections: Vec::new(),
            next_id: 1,
        }
    }

    pub fn add(&mut self, stream: TcpStream) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let conn = Connection::new(id, stream);
        self.connections.push(conn);
        id
    }

    pub fn get_mut(&mut self, id: u64) -> Option<&mut Connection> {
        self.connections.iter_mut().find(|c| c.id() == id)
    }

    pub fn remove(&mut self, id: u64) -> Option<Connection> {
        if let Some(pos) = self.connections.iter().position(|c| c.id() == id) {
            Some(self.connections.remove(pos))
        } else {
            None
        }
    }

    pub fn cleanup_inactive(&mut self) {
        self.connections.retain(|c| c.is_active());
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}
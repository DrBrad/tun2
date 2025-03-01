use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use pcap::packet::layers::ethernet_frame::ip::inter::protocols::Protocols;

#[derive(Clone)]
pub struct Nat {
    mappings: Arc<Mutex<HashMap<(Protocols, Ipv4Addr, u16), (Ipv4Addr, u16)>>>,
    reverse_mappings: Arc<Mutex<HashMap<(Protocols, Ipv4Addr, u16), (Ipv4Addr, u16)>>>,
    timeouts: Arc<Mutex<HashMap<(Protocols, Ipv4Addr, u16), Instant>>>,
}

impl Nat {

    pub fn new() -> Self {
        Self {
            mappings: Arc::new(Mutex::new(HashMap::new())),
            reverse_mappings: Arc::new(Mutex::new(HashMap::new())),
            timeouts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn translate_outbound(&mut self, protocol: Protocols, src_ip: Ipv4Addr, src_port: u16, nat_ip: Ipv4Addr, nat_port: u16) -> (Ipv4Addr, u16) {
        let key = (protocol, src_ip, src_port);

        if let Some(&(new_ip, new_port)) = self.mappings.lock().as_ref().unwrap().get(&key) {
            return (new_ip, new_port);
        }

        self.mappings.lock().as_mut().unwrap().insert(key, (nat_ip, nat_port));
        self.reverse_mappings.lock().as_mut().unwrap().insert((protocol, nat_ip, nat_port), (src_ip, src_port));
        self.timeouts.lock().as_mut().unwrap().insert(key, Instant::now());

        (nat_ip, nat_port)
    }

    pub fn translate_inbound(&mut self, protocol: Protocols, dst_ip: Ipv4Addr, dst_port: u16) -> Option<(Ipv4Addr, u16)> {
        self.reverse_mappings.lock().as_ref().unwrap().get(&(protocol, dst_ip, dst_port)).copied()
    }

    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.timeouts.lock().as_mut().unwrap().retain(|&key, &mut timestamp| now.duration_since(timestamp) < Duration::from_secs(60));
        self.mappings.lock().as_mut().unwrap().retain(|k, _| self.timeouts.lock().as_ref().unwrap().contains_key(k));
        self.reverse_mappings.lock().as_mut().unwrap().retain(|(p, i, s), (d, v)| self.timeouts.lock().as_ref().unwrap().contains_key(&(*p, *d, *v)));
    }
}


//mod types;
mod gateway;
mod tunnel;
mod interface;
mod utils;

use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::thread;
use crate::interface::Interface;
use crate::tunnel::Tunnel;

const DEST_INTERFACE: &str = "wlp7s0"; // Change this to your real interface

const DEST_MAC: [u8; 6] = [0x3c, 0x52, 0xa1, 0x12, 0xa4, 0x50]; // Replace with actual MAC address
const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00]; // IPv4 EtherType
const NEW_DEST_IP: [u8; 4] = [10, 0, 0, 1];
const NEW_SRC_IP: [u8; 4] = [192, 168, 0, 129];

/*
sudo ip addr add 10.0.0.1/24 dev tun0
sudo ip link set dev tun0 up
sudo ip route add default via 10.0.0.1 dev tun0

ping -I tun0 8.8.8.8
sudo tcpdump -i wlp7s0
*/

fn main() -> std::io::Result<()> {
    let tunnel = Tunnel::new("tun0")?;
    let interface = Interface::new(DEST_INTERFACE)?;

    let interface_clone = interface.clone();
    let tunnel_clone = tunnel.try_clone()?;
    thread::spawn(move || {
        loop {
            match interface_clone.read() {
                Ok(buf) => {
                    if buf.len() > 14 {
                        tunnel_clone.write(&buf[14..]);
                    }
                }
                Err(_) => {}
            }
        }
    });

    loop {
        let packet = tunnel.read()?;
        println!("Received packet: {:?}", &packet[..20]);
        interface.write(&packet);
    }
}

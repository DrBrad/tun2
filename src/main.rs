//mod types;
mod tunnel;
mod interface;
mod utils;

use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::thread;
use libc::{c_int, c_ulong};
use crate::interface::Interface;
use crate::tunnel::Tunnel;




pub const AF_INET: i32 = 2;
pub const SOCK_DGRAM: i32 = 2;
pub const SIOCSIFADDR: u64 = 0x00008916;
pub const IFF_TUN: i16 = 0x0001;
pub const IFF_NO_PI: i16 = 0x1000;

pub const IFF_UP: i32 = 0x1;
pub const IFF_RUNNING: i32 = 0x40;
pub const SIOCSIFFLAGS: u64 = 0x00008914;

pub const AF_PACKET: i32 = 17;
pub const ETH_P_ALL: i32 = 0x0003;
pub const SIOCGIFHWADDR: u64 = 0x00008927;
pub const SOCK_RAW: i32 = 3;

pub const SIOCGIFADDR: u64 = 0x8915; // ioctl command for getting IP address





#[repr(C)]
#[derive(Debug)]
struct Ifreq {
    ifr_name: [i8; 16],
    ifr_addr: sockaddr_in,
}

// Structure to store sockaddr_in (IPv4 address)
#[repr(C)]
#[derive(Debug)]
struct sockaddr_in {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [i8; 8],
}







const DEST_INTERFACE: &str = "wlp2s0"; // Change this to your real interface

const DEST_MAC: [u8; 6] = [0xe6, 0x38, 0x83, 0x2e, 0xf3, 0x02]; // Replace with actual MAC address
const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00]; // IPv4 EtherType
const NEW_DEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

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

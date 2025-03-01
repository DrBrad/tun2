mod tunnel;
mod interface;
mod utils;
mod nat;

use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::thread;
use pcap::packet::inter::interfaces::Interfaces;
use pcap::packet::layers::ethernet_frame::arp::arp_extension::ArpExtension;
use pcap::packet::layers::ethernet_frame::arp::inter::arp_operations::ArpOperations;
use pcap::packet::layers::ethernet_frame::ethernet_frame::EthernetFrame;
use pcap::packet::layers::ethernet_frame::inter::ethernet_address::EthernetAddress;
use pcap::packet::layers::ethernet_frame::inter::types::Types;
use pcap::packet::layers::ethernet_frame::ip::inter::protocols::Protocols;
use pcap::packet::layers::ethernet_frame::ip::ipv4_layer::Ipv4Layer;
use pcap::packet::layers::ethernet_frame::ip::tcp::tcp_layer::TcpLayer;
use pcap::packet::layers::ethernet_frame::ip::udp::udp_layer::UdpLayer;
use pcap::packet::layers::inter::layer::Layer;
use pcap::packet::packet::{decode_packet, Packet};
use crate::interface::Interface;
use crate::nat::nat::Nat;
use crate::tunnel::Tunnel;
use crate::utils::interface_utils::{get_address, get_mac, set_mac};

pub const AF_INET: i32 = 2;
pub const SOCK_DGRAM: i32 = 2;
pub const SIOCSIFADDR: u64 = 0x00008916;
pub const IFF_TUN: i16 = 0x0001;
pub const IFF_TAP: i16 = 0x0002;
pub const IFF_NO_PI: i16 = 0x1000;

pub const IFF_UP: i32 = 0x1;
pub const IFF_RUNNING: i32 = 0x40;
pub const SIOCSIFFLAGS: u64 = 0x00008914;

pub const AF_PACKET: i32 = 17;
pub const ETH_P_ALL: i32 = 0x0003;
pub const SIOCGIFHWADDR: u64 = 0x00008927;
pub const SOCK_RAW: i32 = 3;

pub const SIOCGIFADDR: u64 = 0x8915; // ioctl command for getting IP address

pub const SYS_SENDTO: i32 = 0x2C;

pub const SYS_SOCKET: i32 = 41; // Syscall number for `socket` on x86_64 Linux
pub const SYS_IOCTL: i32 = 16;
pub const IFNAMSIZ: usize = 16;
pub const SYS_READ: i32 = 0; // System call number for read on x86_64 Linux
pub const SYS_WRITE: i32 = 1; // System call number for read on x86_64 Linux
pub const SYS_CLOSE: i32 = 3; // System call number for read on x86_64 Linux
pub const SYS_DUP: i32 = 32; // System call number for read on x86_64 Linux
pub const INADDR_ANY: u32 = 0;
pub const SIOCADDRT: i32 = 0x0000890B;
pub const SIOCSIFNETMASK: u64 = 0x0000891C;
pub const SIOCSIFHWADDR: u64 = 0x00008924;
pub const SIOCGIFINDEX: u64 = 0x00008933;

pub const RTF_UP: u16 = 0x0001;
pub const RTF_GATEWAY: u16 = 0x0002;




#[repr(C)]
#[derive(Debug)]
pub struct sockaddr_ll {
    pub sll_family: u16,
    pub sll_protocol: u16,
    pub sll_ifindex: i32,
    pub sll_hatype: u16,
    pub sll_pkttype: u8,
    pub sll_halen: u8,
    pub sll_addr: [u8; 8],
}






#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr {
    pub sa_family: u16,
    pub sa_data: [i8; 14],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __c_anonymous_ifru_map {
    pub mem_start: u64,
    pub mem_end: u64,
    pub base_addr: i16,
    pub irq: u8,
    pub dma: u8,
    pub port: u8,
}

#[repr(C)]
pub union __c_anonymous_ifr_ifru {
    pub ifru_addr: sockaddr,
    pub ifru_dstaddr: sockaddr,
    pub ifru_broadaddr: sockaddr,
    pub ifru_netmask: sockaddr,
    pub ifru_hwaddr: sockaddr,
    pub ifru_flags: i16,
    pub ifru_ifindex: i32,
    pub ifru_metric: i32,
    pub ifru_mtu: i32,
    pub ifru_map: __c_anonymous_ifru_map,
    pub ifru_slave: [i8; IFNAMSIZ],
    pub ifru_newname: [i8; IFNAMSIZ],
    pub ifru_data: *mut i8,
}

#[repr(C)]
pub struct ifreq {
    pub ifr_name: [i8; IFNAMSIZ],
    pub ifr_ifru: __c_anonymous_ifr_ifru,
}

#[repr(C)]
#[derive(Debug)]
pub struct rtentry {
    pub rt_pad1: u64,
    pub rt_dst: sockaddr,
    pub rt_gateway: sockaddr,
    pub rt_genmask: sockaddr,
    pub rt_flags: u16,
    pub rt_pad2: i16,
    pub rt_pad3: u64,
    pub rt_tos: u8,
    pub rt_class: u8,
    #[cfg(target_pointer_width = "64")]
    pub rt_pad4: [i16; 3usize],
    #[cfg(not(target_pointer_width = "64"))]
    pub rt_pad4: c_short,
    pub rt_metric: i16,
    pub rt_dev: *mut i8,
    pub rt_mtu: u64,
    pub rt_window: u64,
    pub rt_irtt: u16,
}







#[repr(C)]
#[derive(Debug)]
struct Ifreq {
    ifr_name: [i8; IFNAMSIZ],
    ifr_addr: sockaddr_in,
}

// Structure to store sockaddr_in (IPv4 address)
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct sockaddr_in {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [i8; 8],
}

extern "C" {
    fn syscall(number: i32, ...) -> i32;
}



//- WE HAVE 2 Ifreq....
// - USE SAME syscall as we do with PCAP


const DEST_INTERFACE: &str = "wlp7s0"; // Change this to your real interface

//const DEST_MAC: [u8; 6] = [0xe6, 0x38, 0x83, 0x2e, 0xf3, 0x02]; // Replace with actual MAC address
//const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00]; // IPv4 EtherType


const DEFAULT_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const DEFAULT_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const DEFAULT_NET_MASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);


fn main() -> std::io::Result<()> {
    let tunnel = Tunnel::new("tap0")?;
    let interface = Interface::new(DEST_INTERFACE)?;
    let mut nat = Nat::new();

    let device_mac = EthernetAddress::new(0xc0, 0xde, 0xb1, 0xee, 0xd0, 0x00);
    let gateway_mac = EthernetAddress::new(0xca, 0x7e, 0xb1, 0xee, 0xd0, 0x00);
    let broadcast_mac = EthernetAddress::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

    set_mac("tap0", device_mac)?;

    println!("{:?}", device_mac.to_string());

    let interface_mac = get_mac(DEST_INTERFACE)?;
    let interface_address = get_address(DEST_INTERFACE)?;
    let interface_gateway_mac = EthernetAddress::new(0x3c, 0x52, 0xa1, 0x12, 0xa4, 0x50);

    println!("{}", interface_mac.to_string());
    println!("{}", interface_address.to_string());
    println!("{}", interface_gateway_mac.to_string());


    let interface_clone = interface.clone();
    let tunnel_clone = tunnel.try_clone()?;
    let mut nat_clone = nat.clone();
    thread::spawn(move || {
        loop {
            let buf = interface_clone.read().unwrap();
            let mut packet = decode_packet(Interfaces::Ethernet, &buf);

            let mut ethernet_frame = packet.get_frame_mut().as_any_mut().downcast_mut::<EthernetFrame>().unwrap();

            if ethernet_frame.get_destination_mac().eq(&interface_mac) {
                match ethernet_frame.get_type() {
                    Types::IPv4 => {
                        ethernet_frame.set_source_mac(gateway_mac);
                        ethernet_frame.set_destination_mac(device_mac);

                        let mut ipv4_layer = ethernet_frame.get_data_mut().unwrap().as_any_mut().downcast_mut::<Ipv4Layer>().unwrap();


                        match ipv4_layer.get_protocol() {
                            Protocols::Tcp => {
                                let tcp_layer = ipv4_layer.get_data().unwrap().as_any().downcast_ref::<TcpLayer>().unwrap();
                                match nat_clone.translate_inbound(ipv4_layer.get_protocol(), ipv4_layer.get_destination_address(), tcp_layer.get_destination_port()) {
                                    Some((address, port)) => {
                                        ipv4_layer.set_destination_address(address);
                                        ipv4_layer.compute_checksum();
                                        tunnel_clone.write(&packet.to_bytes());
                                    }
                                    None => {}
                                }
                            }
                            Protocols::Udp => {
                                let udp_layer = ipv4_layer.get_data().unwrap().as_any().downcast_ref::<UdpLayer>().unwrap();
                                match nat_clone.translate_inbound(ipv4_layer.get_protocol(), ipv4_layer.get_destination_address(), udp_layer.get_destination_port()) {
                                    Some((address, port)) => {
                                        ipv4_layer.set_destination_address(address);
                                        ipv4_layer.compute_checksum();
                                        tunnel_clone.write(&packet.to_bytes());
                                    }
                                    None => {}
                                }
                            }
                            _ => {
                                match nat_clone.translate_inbound(ipv4_layer.get_protocol(), ipv4_layer.get_destination_address(), 0) {
                                    Some((address, port)) => {
                                        ipv4_layer.set_destination_address(address);
                                        ipv4_layer.compute_checksum();
                                        tunnel_clone.write(&packet.to_bytes());
                                    }
                                    None => {}
                                }
                            }
                        }


                    }
                    _ => {
                        //tunnel_clone.write(&packet.to_bytes());
                    }
                }
            }
            nat_clone.cleanup();
        }
    });


    loop {
        let buf = tunnel.read()?;

        let mut packet = decode_packet(Interfaces::Ethernet, &buf);


        let mut ethernet_frame = packet.get_frame_mut().as_any_mut().downcast_mut::<EthernetFrame>().unwrap();

        if ethernet_frame.get_source_mac().eq(&device_mac) {
            match ethernet_frame.get_type() {
                Types::Arp => {
                    let arp_layer = ethernet_frame.get_data().unwrap().as_any().downcast_ref::<ArpExtension>().unwrap();

                    if !ethernet_frame.get_destination_mac().eq(&broadcast_mac) {
                        continue
                    }

                    if arp_layer.get_target_address().eq(&DEFAULT_GATEWAY) {
                        println!("ARP");
                        let mut ethernet_frame_r = EthernetFrame::new(ethernet_frame.get_source_mac(), gateway_mac, Types::Arp);
                        let mut arp_layer_r = ArpExtension::new(ArpOperations::Reply, gateway_mac, DEFAULT_GATEWAY, arp_layer.get_sender_mac(), arp_layer.get_sender_address());
                        arp_layer_r.compute_length();
                        ethernet_frame_r.set_data(Box::new(arp_layer_r));

                        ethernet_frame_r.compute_length();

                        tunnel.write(&ethernet_frame_r.to_bytes())?;
                    }
                }
                Types::IPv4 => {

                    /*
                    let ipv4_layer = ethernet_frame.get_data().unwrap().as_any().downcast_ref::<Ipv4Layer>().unwrap();

                    if !ipv4_layer.get_source_address().eq(&DEFAULT_ADDRESS) {
                        continue
                    }
                    */

                    ethernet_frame.set_source_mac(interface_mac);
                    ethernet_frame.set_destination_mac(interface_gateway_mac);

                    let mut ipv4_layer = ethernet_frame.get_data_mut().unwrap().as_any_mut().downcast_mut::<Ipv4Layer>().unwrap();

                    match ipv4_layer.get_protocol() {
                        Protocols::Tcp => {
                            let tcp_layer = ipv4_layer.get_data().unwrap().as_any().downcast_ref::<TcpLayer>().unwrap();
                            match nat.translate_outbound(ipv4_layer.get_protocol(), ipv4_layer.get_source_address(), tcp_layer.get_source_port(), interface_address, tcp_layer.get_source_port()) {
                                (address, port) => {
                                    ipv4_layer.set_source_address(address);
                                }
                            }
                            ipv4_layer.compute_checksum();

                            interface.write(&packet.to_bytes())?;
                        }
                        Protocols::Udp => {
                            let udp_layer = ipv4_layer.get_data().unwrap().as_any().downcast_ref::<UdpLayer>().unwrap();
                            match nat.translate_outbound(ipv4_layer.get_protocol(), ipv4_layer.get_source_address(), udp_layer.get_source_port(), interface_address, udp_layer.get_source_port()) {
                                (address, port) => {
                                    ipv4_layer.set_source_address(address);
                                }
                            }
                            ipv4_layer.compute_checksum();

                            interface.write(&packet.to_bytes())?;
                        }
                        _ => {
                            nat.translate_outbound(ipv4_layer.get_protocol(), ipv4_layer.get_source_address(), 0, interface_address, 0);
                            ipv4_layer.set_source_address(interface_address);
                            ipv4_layer.compute_checksum();

                            interface.write(&packet.to_bytes())?;
                        }
                    }

                }
                _ => {
                    //interface.write(&packet.to_bytes())?;
                }
            }
        }
        nat.cleanup();
    }
}

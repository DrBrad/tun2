//mod types;
mod tunnel;
mod interface;
mod utils;

use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::thread;
use pcap::packet::inter::interfaces::Interfaces;
use pcap::packet::layers::ethernet_frame::inter::ethernet_address::EthernetAddress;
use pcap::packet::packet::decode_packet;
use crate::interface::Interface;
use crate::tunnel::Tunnel;
use crate::utils::arp::send_arp_reply;

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
struct Ifreq {
    ifr_name: [i8; IFNAMSIZ],
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

extern "C" {
    fn syscall(number: i32, ...) -> i32;
}





const DEST_INTERFACE: &str = "wlp7s0"; // Change this to your real interface

const DEST_MAC: [u8; 6] = [0xe6, 0x38, 0x83, 0x2e, 0xf3, 0x02]; // Replace with actual MAC address
const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00]; // IPv4 EtherType
const NEW_DEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 25);

/*
sudo ip addr add 10.0.0.1/24 dev tun0
sudo ip link set dev tun0 up
sudo ip route add default via 10.0.0.1 dev tun0

ping -I tun0 8.8.8.8
sudo tcpdump -i wlp7s0

sudo ip addr add 172.16.0.25/16 dev tap0
sudo ip link set dev tap0 address aa:bb:cc:dd:ee:ff
sudo ip link set dev tap0 up



sudo dhclient tap0


sudo ip route add default via 172.16.0.1 dev tap0

sudo ip neigh add 8.8.8.8 lladdr aa:bb:ff:dd:ee:ff dev tap0
sudo ip neigh add 10.0.0.1 lladdr aa:bb:ff:dd:ee:ff dev tap0
*/

fn main() -> std::io::Result<()> {
    let tunnel = Tunnel::new("tap0")?;
    //let interface = Interface::new(DEST_INTERFACE)?;

    /*
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
    */
    /*
    ARP

    Request
    Source
    Destination

    SenderMac = Source
    SenderIP = Source IP
    TargetMac = NULL
    TargetIP = Requested IP


    Reply
    Source
    Destination

    SenderMac = Source
    SenderIp = Source IP
    TargetMac = Requesters Mac
    TargetIP = Requested IP

    */

    //let device_mac = EthernetAddress::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
    //let nat_mac = EthernetAddress::new(0xaa, 0xbb, 0xff, 0xdd, 0xee, 0xff);
    //let broadcast_mac = EthernetAddress::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);



    let broadcast_mac = EthernetAddress::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    let broadcast_ip = Ipv4Addr::new(255, 255, 255, 255);

    loop {
        let buf = tunnel.read()?;

        let packet = decode_packet(Interfaces::Ethernet, &buf);
        println!("{:?}", packet);







        //DHCP ATTEMPT


        /*
        let ethernet_layer = packet.get_frame(0).unwrap().as_any().downcast_ref::<EthernetLayer>().unwrap();
        if ethernet_layer.get_destination().eq(&broadcast_mac) {

            println!("{:?}", packet);

            match ethernet_layer.get_type() {
                Types::IPv4 => {
                    let ipv4_layer = packet.get_layer(1).unwrap().as_any().downcast_ref::<Ipv4Layer>().unwrap();

                    if ipv4_layer.get_destination_ip().eq(&broadcast_ip) {

                        match ipv4_layer.get_protocol() {
                            Protocols::Udp => {

                                println!("DHCP");





                            }
                            _ => {}
                        }

                    }



                }
                Types::Arp => {}
                Types::IPv6 => {}
                _ => {}
            }

        }*/











        /*

        let ethernet_layer = packet.get_layer(0).unwrap().as_any().downcast_ref::<EthernetLayer>().unwrap();

        if ethernet_layer.get_destination().equals(&broadcast_mac) {
            println!("MATCH");

            match ethernet_layer.get_type() {
                Types::Arp => {
                    let arp_layer = packet.get_layer(1).unwrap().as_any().downcast_ref::<ArpLayer>().unwrap();

                    //REQUEST
                    //source = 3c:52:a1:12:a4:50
                    //destination = ff:ff:ff:ff:ff:ff

                    //sender = 3c:52:a1:12:a4:50
                    //sender = 192.168.0.1

                    //target = 00:00:00:00:00:00
                    //target = 192.168.0.129



                    //REPLY
                    //source = 1c:ce:51:34:00:9f
                    //destination = 3c:52:a1:12:a4:50

                    //sender = 1c:ce:51:34:00:9f
                    //sender = 192.168.0.129

                    //target = 3c:52:a1:12:a4:50
                    //target = 192.168.0.1



                    //PLAN
                    //source = xx:xx:xx:xx:xx:xx
                    //destination = requests source

                    //sender = xx:xx:xx:xx:xx:xx
                    //sender = requests target

                    //target = requests sender
                    //target = requests sender

                    //println!("{:?}    {:X?}", &packet, &buf);//&packet[..20]);
                    send_arp_reply("tap0", nat_mac, arp_layer.get_target_ip(), arp_layer.get_sender_mac(), arp_layer.get_sender_ip());

                }
                _ => {
                    //interface.write(&buf);
                }
            }
        }
        */


    }
}

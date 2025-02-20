mod types;
mod gateway;

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::{mem, thread};
use std::process::Command;
use libc::{c_int, c_short, c_ulong, ifreq, ioctl, IFF_TUN, IFF_NO_PI, O_RDWR, SOCK_RAW, AF_PACKET, ETH_P_ALL, sockaddr_ll, socket, sendto, sockaddr, AF_INET, SIOCGIFHWADDR, SOCK_DGRAM, htons, ETH_P_ARP};
use crate::types::Types;

const TUN_DEVICE: &str = "/dev/net/tun";
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

fn create_tun_interface(name: &str) -> std::io::Result<File> {
    let file = File::options().read(true).write(true).open(TUN_DEVICE)?;

    let fd = file.as_raw_fd();
    let mut ifr: ifreq = unsafe { mem::zeroed() };

    let name_bytes = name.as_bytes();
    let name_i8: Vec<i8> = name_bytes.iter().map(|&b| b as i8).collect();
    ifr.ifr_name[..name_i8.len()].copy_from_slice(&name_i8);

    ifr.ifr_ifru.ifru_flags = (IFF_TUN | IFF_NO_PI) as c_short;

    let ret = unsafe { ioctl(fd, 0x400454ca, &mut ifr as *mut _) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(file)
}

fn read_from_tun(file: &File) -> std::io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; 4096];
    let len = unsafe { libc::read(file.as_raw_fd(), buffer.as_mut_ptr() as *mut _, buffer.len()) };

    if len < 0 {
        return Err(std::io::Error::last_os_error());
    }

    buffer.truncate(len as usize);
    Ok(buffer)
}

/*
fn write_to_interface(socket_fd: RawFd, packet: &[u8], dest_ifindex: i32) -> std::io::Result<()> {
    let mut sockaddr: sockaddr_ll = unsafe { mem::zeroed() };
    sockaddr.sll_family = AF_PACKET as u16;
    sockaddr.sll_ifindex = dest_ifindex;
    sockaddr.sll_protocol = (ETH_P_ALL as u16).to_be();

    let res = unsafe {
        sendto(
            socket_fd,
            packet.as_ptr() as *const _,
            packet.len(),
            0,
            &sockaddr as *const sockaddr_ll as *const _,
            mem::size_of::<sockaddr_ll>() as u32,
        )
    };

    if res < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}
*/

fn write_to_tun(file: &File, packet: &[u8]) -> std::io::Result<()> {
    let mut modified_packet = packet.to_vec();
    modify_ip_packet_2(&mut modified_packet); // Change the source IP

    //println!("Sending packet with length: {}", packet.len());
    //let len = unsafe { libc::write(file.as_raw_fd(), packet.as_ptr() as *const _, packet.len()) };
    let len = unsafe { libc::write(file.as_raw_fd(), modified_packet.as_ptr() as *const _, modified_packet.len()) };
    //println!("Length: {}", len);

    if len < 0 {
        println!("{}", std::io::Error::last_os_error());
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}




// Compute checksum (needed after modifying IP header)
fn compute_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..data.len()).step_by(2) {
        let word = if i + 1 < data.len() {
            u16::from_be_bytes([data[i], data[i + 1]])
        } else {
            u16::from_be_bytes([data[i], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }

    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

// Modify source IP in an IPv4 packet
fn modify_ip_packet(packet: &mut [u8]) {
    if packet.len() < 20 {
        return; // Too short to be an IPv4 packet
    }

    let ihl = (packet[0] & 0x0F) as usize * 4; // Internet Header Length (IHL)
    if ihl < 20 || ihl > packet.len() {
        return; // Invalid IHL
    }

    // Modify source IP (bytes 12-15 in IPv4 header)
    packet[12..16].copy_from_slice(&NEW_SRC_IP);

    // Zero out checksum before recalculating
    packet[10] = 0;
    packet[11] = 0;

    // Recalculate checksum
    let checksum = compute_checksum(&packet[..ihl]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
}


fn modify_ip_packet_2(packet: &mut [u8]) {
    if packet.len() < 20 {
        return; // Too short to be an IPv4 packet
    }

    let ihl = (packet[0] & 0x0F) as usize * 4; // Internet Header Length (IHL)
    if ihl < 20 || ihl > packet.len() {
        return; // Invalid IHL
    }

    // Modify source IP (bytes 12-15 in IPv4 header)
    packet[16..20].copy_from_slice(&NEW_DEST_IP);

    // Zero out checksum before recalculating
    packet[10] = 0;
    packet[11] = 0;

    // Recalculate checksum
    let checksum = compute_checksum(&packet[..ihl]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
}



fn send_packet(socket_fd: RawFd, interface_index: i32, src_mac: [u8; 6], mut packet: &[u8]) -> std::io::Result<()> {
    let mut modified_packet = packet.to_vec();
    modify_ip_packet(&mut modified_packet); // Change the source IP

    let mut eth_frame = Vec::new();
    eth_frame.extend_from_slice(&DEST_MAC);
    eth_frame.extend_from_slice(&src_mac);
    eth_frame.extend_from_slice(&ETHERTYPE_IPV4);
    //packet.to_vec().splice(12..16, Ipv4Addr::from([10, 1, 12, 143]).octets());
    eth_frame.extend_from_slice(&modified_packet); // Append IP packet

    println!("{:x?}", eth_frame);

    let sll = sockaddr_ll {
        sll_family: AF_PACKET as u16,
        sll_protocol: (ETH_P_ALL as u16).to_be(),
        sll_ifindex: interface_index,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };

    let ret = unsafe {
        sendto(
            socket_fd,
            eth_frame.as_ptr() as *const _,
            eth_frame.len(),
            0,
            &sll as *const _ as *const sockaddr,
            mem::size_of::<sockaddr_ll>() as u32,
        )
    };

    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..data.len()).step_by(2) {
        let word = if i + 1 < data.len() {
            (data[i] as u16) << 8 | (data[i + 1] as u16)
        } else {
            (data[i] as u16) << 8 // Last odd byte
        };
        sum += word as u32;
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn fix_ip_checksum(packet: &mut [u8]) {
    packet[10] = 0x00;
    packet[11] = 0x00;
    let checksum = calculate_checksum(&packet[0..20]);
    packet[10] = (checksum >> 8) as u8;
    packet[11] = (checksum & 0xFF) as u8;
}




fn create_raw_socket() -> std::io::Result<RawFd> {
    let socket_fd = unsafe { socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as i32) };
    if socket_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(socket_fd)
}


fn get_interface_index(interface: &str) -> std::io::Result<i32> {
    let socket_fd = unsafe { socket(AF_PACKET, SOCK_RAW, ETH_P_ALL.to_be() as i32) };
    if socket_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut ifr: ifreq = unsafe { mem::zeroed() };
    let name_bytes = interface.as_bytes();
    let name_i8: Vec<i8> = name_bytes.iter().map(|&b| b as i8).collect();
    ifr.ifr_name[..name_i8.len()].copy_from_slice(&name_i8);

    let ret = unsafe { ioctl(socket_fd, 0x8933, &mut ifr as *mut _) }; // SIOCGIFINDEX
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    unsafe { libc::close(socket_fd) };

    Ok(unsafe { ifr.ifr_ifru.ifru_ifindex })
}








fn get_mac_address(interface: &str) -> std::io::Result<[u8; 6]> {
    let fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut ifr: ifreq = unsafe { mem::zeroed() };

    // Convert &str to [i8; IFNAMSIZ] (interface name)
    let mut name_bytes = [0i8; libc::IFNAMSIZ];
    for (i, &b) in interface.as_bytes().iter().enumerate() {
        name_bytes[i] = b as i8;
    }
    ifr.ifr_name.copy_from_slice(&name_bytes);

    let ret = unsafe { ioctl(fd, SIOCGIFHWADDR, &mut ifr) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    unsafe { libc::close(fd) };

    let mac = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data };
    Ok([mac[0] as u8, mac[1] as u8, mac[2] as u8, mac[3] as u8, mac[4] as u8, mac[5] as u8])
}














fn main() -> std::io::Result<()> {
    let tun_file = create_tun_interface("tun0")?;
    println!("TUN interface created: tun0");

    let dest_ifindex = get_interface_index(DEST_INTERFACE)?;
    println!("Forwarding packets to interface index: {}", dest_ifindex);

    let socket_fd = create_raw_socket()?;


    let src_mac = get_mac_address(DEST_INTERFACE)?;
    //let dst_mac = get_router_mac(DEST_INTERFACE).unwrap();

    let tun_file_clone = tun_file.try_clone()?;
    thread::spawn(move || {
        loop {
            let mut buffer = vec![0u8; 4096];
            let len = unsafe { libc::read(socket_fd, buffer.as_mut_ptr() as *mut _, buffer.len()) };
            if len > 0 {
                buffer.truncate(len as usize);


                if buffer.len() > 14 {
                    write_to_tun(&tun_file_clone, &buffer[14..]);
                }

                /*

                let _type = Types::get_type_from_code(u16::from_be_bytes([buffer[12], buffer[13]])).unwrap();

                match _type {
                    Types::IPv4 => {
                        //println!("WLP: {}", Protocols::get_protocol_from_code(buffer[23]).unwrap().to_string());

                        if buffer.len() > 14 {
                            write_to_tun(&tun_file_clone, &buffer[14..]);
                        }
                    }
                    Types::Arp => {}
                    Types::IPv6 => {
                        //println!("WLP: {}", Protocols::get_protocol_from_code(buffer[20]).unwrap().to_string());
                    }
                    Types::Broadcast => {}
                }*/

            }
        }
    });

    loop {
        let packet = read_from_tun(&tun_file)?;
        println!("Received packet: {:?}", &packet[..20]);

        send_packet(socket_fd.clone(), dest_ifindex, src_mac, &packet)?;

        //AT THIS POINT WE HAVE IPHeader and on of packet, we should be able to write it directly
        //to a raw socket and expect a response

        /*
        write_to_interface(socket_fd, &packet, dest_ifindex)?;
        println!("Forwarded packet to {}", DEST_INTERFACE);
        */


        //println!("LOOP");
    }
}

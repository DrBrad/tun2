use std::ffi::{c_void, CString};
use std::{mem, ptr};
use std::net::Ipv4Addr;
use libc::{c_int, htons, ifreq, ioctl, sendto, sockaddr_ll, socket, AF_PACKET, ETH_P_ARP, SIOCGIFINDEX};
use pcap::packet::layers::layer_2::inter::ethernet_address::EthernetAddress;
use crate::SOCK_RAW;

#[repr(C, packed)]
struct EthernetFrame {
    dest_mac: [u8; 6],
    src_mac: [u8; 6],
    ethertype: u16,
    arp: ArpPacket,
}

#[repr(C, packed)]
struct ArpPacket {
    htype: u16,
    ptype: u16,
    hlen: u8,
    plen: u8,
    oper: u16,
    sha: [u8; 6], // Source MAC
    spa: [u8; 4], // Source IP
    tha: [u8; 6], // Target MAC
    tpa: [u8; 4], // Target IP
}

pub fn send_arp_reply(interface: &str, sender_mac: EthernetAddress, sender_ip: Ipv4Addr, target_mac: EthernetAddress, target_ip: Ipv4Addr) {
    // Create raw socket
    let sock = unsafe { socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP as u16) as c_int) };
    if sock < 0 {
        eprintln!("Error creating socket");
        return;
    }

    // Get the interface index
    let ifreq_name = CString::new(interface).expect("CString::new failed");
    let mut ifreq: ifreq = unsafe { mem::zeroed() };
    unsafe {
        ptr::copy_nonoverlapping(ifreq_name.as_ptr(), ifreq.ifr_name.as_mut_ptr(), ifreq_name.to_bytes().len());
        if ioctl(sock, SIOCGIFINDEX, &mut ifreq) < 0 {
            eprintln!("Error getting interface index");
            libc::close(sock);
            return;
        }
    }

    // Construct the sockaddr_ll struct
    let mut sockaddr: sockaddr_ll = unsafe { mem::zeroed() };
    sockaddr.sll_family = AF_PACKET as u16;
    sockaddr.sll_protocol = htons(ETH_P_ARP as u16);
    sockaddr.sll_ifindex = unsafe { ifreq.ifr_ifru.ifru_ifindex };
    sockaddr.sll_halen = 6;
    sockaddr.sll_addr[..6].copy_from_slice(&target_mac.to_bytes());

    // Construct the Ethernet + ARP packet
    let eth_arp = EthernetFrame {
        dest_mac: target_mac.to_bytes(), // Destination MAC (who requested ARP)
        src_mac: sender_mac.to_bytes(),  // Our MAC address
        ethertype: htons(ETH_P_ARP as u16),
        arp: ArpPacket {
            htype: htons(1),       // Ethernet
            ptype: htons(0x0800),  // IPv4
            hlen: 6,
            plen: 4,
            oper: htons(2),        // ARP Reply
            sha: sender_mac.to_bytes(),       // Sender MAC (our MAC)
            spa: sender_ip.octets(), // Sender IP (gateway IP)
            tha: target_mac.to_bytes(),       // Target MAC (who requested)
            tpa: target_ip.octets(), // Target IP
        },
    };

    // Send the Ethernet + ARP frame
    unsafe {
        let sent_len = sendto(
            sock,
            &eth_arp as *const _ as *const c_void,
            mem::size_of::<EthernetFrame>(),
            0,
            &sockaddr as *const sockaddr_ll as *const _,
            mem::size_of::<sockaddr_ll>() as u32,
        );

        if sent_len < 0 {
            eprintln!("Error sending ARP reply: {}", std::io::Error::last_os_error());
        }
    }

    // Close the socket
    unsafe {
        libc::close(sock);
    }
}

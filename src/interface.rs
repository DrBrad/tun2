use std::{io, mem};
use std::os::fd::RawFd;
use libc::{ifreq, ioctl, sendto, sockaddr, sockaddr_ll, socket, AF_INET, AF_PACKET, ETH_P_ALL, SIOCGIFHWADDR, SOCK_DGRAM, SOCK_RAW};
use crate::{DEST_MAC, ETHERTYPE_IPV4, NEW_SRC_IP};
use crate::utils::ip_utils::compute_checksum;

#[derive(Clone)]
pub struct Interface {
    interface: String,
    interface_index: i32,
    source_mac: [u8; 6],
    fd: RawFd
}

impl Interface {

    pub fn new(interface: &str) -> io::Result<Self> {
        let fd = unsafe { socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as i32) };
        //let fd = unsafe { socket(AF_PACKET, SOCK_RAW, ETH_P_ALL.to_be()) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let interface_index = Self::get_interface_index(interface)?;
        let source_mac = Self::get_mac_address(interface)?;

        Ok(Self {
            interface: interface.to_string(),
            interface_index,
            source_mac,
            fd
        })
    }

    pub fn read(&self) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; 4096];
        let len = unsafe { libc::read(self.fd, buffer.as_mut_ptr() as *mut _, buffer.len()) };
        if len > 0 {
            buffer.truncate(len as usize);
            return Ok(buffer);
        }

        Err(io::Error::last_os_error())
    }

    pub fn write(&self, packet: &[u8]) -> io::Result<()> {
        let packet = packet.to_vec();
        let mut packet = packet.to_vec();
        if packet.len() < 20 {
            return Err(io::Error::new(io::ErrorKind::Other, "Packet length too small")); // Too short to be an IPv4 packet
        }

        let ihl = (packet[0] & 0x0F) as usize * 4; // Internet Header Length (IHL)
        if ihl < 20 || ihl > packet.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "Packet has invalid IHL")); // Too short to be an IPv4 packet
        }

        // Modify source IP (bytes 12-15 in IPv4 header)
        packet[12..16].copy_from_slice(&NEW_SRC_IP);

        // Zero out checksum before recalculating
        packet[10] = 0;
        packet[11] = 0;

        // Recalculate checksum
        let checksum = compute_checksum(&packet[..ihl]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());

        let mut eth_frame = Vec::new();
        eth_frame.extend_from_slice(&DEST_MAC);
        eth_frame.extend_from_slice(&self.source_mac);
        eth_frame.extend_from_slice(&ETHERTYPE_IPV4);
        eth_frame.extend_from_slice(&packet); // Append IP packet

        println!("{:x?}", eth_frame);

        let sll = sockaddr_ll {
            sll_family: AF_PACKET as u16,
            sll_protocol: (ETH_P_ALL as u16).to_be(),
            sll_ifindex: self.interface_index,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };

        let ret = unsafe {
            sendto(
                self.fd,
                eth_frame.as_ptr() as *const _,
                eth_frame.len(),
                0,
                &sll as *const _ as *const sockaddr,
                mem::size_of::<sockaddr_ll>() as u32,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    fn get_interface_index(interface: &str) -> io::Result<i32> {
        let fd = unsafe { socket(AF_PACKET, SOCK_RAW, ETH_P_ALL.to_be()) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut ifr: ifreq = unsafe { mem::zeroed() };
        let name_bytes = interface.as_bytes();
        let name_i8: Vec<i8> = name_bytes.iter().map(|&b| b as i8).collect();
        ifr.ifr_name[..name_i8.len()].copy_from_slice(&name_i8);

        let ret = unsafe { ioctl(fd, 0x8933, &mut ifr as *mut _) }; // SIOCGIFINDEX
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe { libc::close(fd) };

        Ok(unsafe { ifr.ifr_ifru.ifru_ifindex })
    }

    fn get_mac_address(interface: &str) -> io::Result<[u8; 6]> {
        let fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
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
            return Err(io::Error::last_os_error());
        }

        unsafe { libc::close(fd) };

        let mac = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data };
        Ok([mac[0] as u8, mac[1] as u8, mac[2] as u8, mac[3] as u8, mac[4] as u8, mac[5] as u8])
    }
}

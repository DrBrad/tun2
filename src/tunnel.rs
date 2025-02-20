use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::{io, mem, thread};
use std::os::fd::FromRawFd;
use std::process::Command;
use libc::{c_int, c_short, c_ulong, ifreq, ioctl, IFF_TUN, IFF_NO_PI, O_RDWR, SOCK_RAW, AF_PACKET, ETH_P_ALL, sockaddr_ll, socket, sendto, sockaddr, AF_INET, SIOCGIFHWADDR, SOCK_DGRAM, htons, ETH_P_ARP};
use crate::types::Types;
use crate::{calculate_checksum, compute_checksum, NEW_DEST_IP};

const TUN_DEVICE: &str = "/dev/net/tun";

//#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct Tunnel {
    file: File
}

impl Tunnel {

    pub fn new(name: &str) -> io::Result<Self> {
        let file = File::options().read(true).write(true).open(TUN_DEVICE)?;

        let fd = file.as_raw_fd();
        let mut ifr: ifreq = unsafe { mem::zeroed() };

        let name_bytes = name.as_bytes();
        let name_i8: Vec<i8> = name_bytes.iter().map(|&b| b as i8).collect();
        ifr.ifr_name[..name_i8.len()].copy_from_slice(&name_i8);

        ifr.ifr_ifru.ifru_flags = (IFF_TUN | IFF_NO_PI) as c_short;

        let ret = unsafe { ioctl(fd, 0x400454ca, &mut ifr as *mut _) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        println!("{}", ret);

        Ok(Self {
            file
        })
    }

    pub fn read(&self) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; 4096];
        let len = unsafe { libc::read(self.file.as_raw_fd(), buffer.as_mut_ptr() as *mut _, buffer.len()) };

        if len < 0 {
            return Err(io::Error::last_os_error());
        }

        buffer.truncate(len as usize);
        Ok(buffer)
    }

    pub fn write(&self, packet: &[u8]) -> io::Result<()> {
        let mut packet = packet.to_vec();
        if packet.len() < 20 {
            return Err(io::Error::new(io::ErrorKind::Other, "Packet length too small")); // Too short to be an IPv4 packet
        }

        let ihl = (packet[0] & 0x0F) as usize * 4; // Internet Header Length (IHL)
        if ihl < 20 || ihl > packet.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "Packet has invalid IHL")); // Too short to be an IPv4 packet
        }

        // Modify source IP (bytes 12-15 in IPv4 header)
        packet[16..20].copy_from_slice(&NEW_DEST_IP);

        // Zero out checksum before recalculating
        packet[10] = 0;
        packet[11] = 0;

        // Recalculate checksum
        let checksum = compute_checksum(&packet[..ihl]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());

        let len = unsafe { libc::write(self.file.as_raw_fd(), packet.as_ptr() as *const _, packet.len()) };

        if len < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        let fd = unsafe { libc::dup(self.file.as_raw_fd()) };
        if fd == -1 {
            return Err(io::Error::last_os_error());
        }

        let new_file = unsafe { File::from_raw_fd(fd) };

        Ok(Self {
            file: new_file
        })
    }
}

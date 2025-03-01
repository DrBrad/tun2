use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::{io, mem, thread};
use std::ffi::CString;
use std::os::fd::FromRawFd;
use libc::{c_char, c_short, in_addr, SIOCADDRT};
use crate::{AF_INET, IFF_NO_PI, IFF_RUNNING, IFF_TUN, IFF_UP, SIOCSIFADDR, SIOCSIFFLAGS, SOCK_DGRAM, ifreq, sockaddr_in, syscall, SYS_SOCKET, AF_PACKET, SOCK_RAW, ETH_P_ALL, SYS_IOCTL, SYS_READ, SYS_WRITE, SYS_DUP, IFF_TAP, sockaddr, IFNAMSIZ, DEFAULT_NET_MASK, DEFAULT_ADDRESS, DEFAULT_GATEWAY};
use crate::utils::interface_utils::{add_default_route, bring_up, set_ip};

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

        ifr.ifr_ifru.ifru_flags = IFF_TAP | IFF_NO_PI;

        let ret = unsafe { syscall(SYS_IOCTL, fd, 0x400454ca, &mut ifr as *mut _) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        set_ip(name, DEFAULT_ADDRESS, DEFAULT_NET_MASK)?;
        bring_up(name)?;
        add_default_route(name, DEFAULT_GATEWAY)?;

        Ok(Self {
            file
        })
    }

    pub fn read(&self) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; 4096];
        let len = unsafe { syscall(SYS_READ, self.file.as_raw_fd(), buffer.as_mut_ptr() as *mut _, buffer.len()) };

        if len < 0 {
            return Err(io::Error::last_os_error());
        }

        buffer.truncate(len as usize);
        Ok(buffer)
    }

    pub fn write(&self, packet: &[u8]) -> io::Result<()> {
        /*
        let mut packet = packet.to_vec();
        if packet.len() < 20 {
            return Err(io::Error::new(io::ErrorKind::Other, "Packet length too small")); // Too short to be an IPv4 packet
        }

        let ihl = (packet[0] & 0x0F) as usize * 4; // Internet Header Length (IHL)
        if ihl < 20 || ihl > packet.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "Packet has invalid IHL")); // Too short to be an IPv4 packet
        }

        packet[16..20].copy_from_slice(&NEW_DEST_IP.octets());

        packet[10] = 0;
        packet[11] = 0;

        let checksum = compute_checksum(&packet[..ihl]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        */

        let len = unsafe { syscall(SYS_WRITE, self.file.as_raw_fd(), packet.as_ptr() as *const _, packet.len()) };

        if len < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        let fd = unsafe { syscall(SYS_DUP, self.file.as_raw_fd()) };
        if fd == -1 {
            return Err(io::Error::last_os_error());
        }

        let new_file = unsafe { File::from_raw_fd(fd) };

        Ok(Self {
            file: new_file
        })
    }
}







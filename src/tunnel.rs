use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::{io, mem, thread};
use std::os::fd::FromRawFd;
use std::process::Command;
use libc::{ifreq, ioctl, socket, sockaddr_in};
use crate::{NEW_DEST_IP, AF_INET, IFF_NO_PI, IFF_RUNNING, IFF_TUN, IFF_UP, SIOCSIFADDR, SIOCSIFFLAGS, SOCK_DGRAM};
use crate::utils::ip_utils::compute_checksum;

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

        ifr.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;

        let ret = unsafe { ioctl(fd, 0x400454ca, &mut ifr as *mut _) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Self::set_ip(name, NEW_DEST_IP)?;
        Self::bring_up(name)?;

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

        packet[16..20].copy_from_slice(&NEW_DEST_IP.octets());

        packet[10] = 0;
        packet[11] = 0;

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



    fn set_ip(interface: &str, ip: Ipv4Addr) -> io::Result<()> {
        let sock_fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
        if sock_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut ifr: ifreq = unsafe { mem::zeroed() };
        //let name_bytes = interface.as_bytes();
        //ifr.ifr_name[..name_bytes.len()].copy_from_slice(name_bytes);


        let name_bytes = interface.as_bytes();
        let name_i8: Vec<i8> = name_bytes.iter().map(|&b| b as i8).collect();
        ifr.ifr_name[..name_i8.len()].copy_from_slice(&name_i8);

        // Convert string IP to sockaddr
        let mut sockaddr: sockaddr_in = unsafe { mem::zeroed() };
        sockaddr.sin_family = AF_INET as u16;
        sockaddr.sin_addr.s_addr = u32::from(ip).to_be();//ip.parse::<Ipv4Addr>().unwrap().into();

        unsafe {
            let addr_ptr = &sockaddr as *const _ as *const libc::c_void;
            std::ptr::copy_nonoverlapping(addr_ptr, &mut ifr.ifr_ifru as *mut _ as *mut libc::c_void, mem::size_of::<sockaddr_in>());
        }

        let ret = unsafe { ioctl(sock_fd, SIOCSIFADDR, &ifr) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    fn bring_up(interface: &str) -> io::Result<()> {
        let sock_fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
        if sock_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut ifr: ifreq = unsafe { mem::zeroed() };
        let name_bytes = interface.as_bytes();
        let name_i8: Vec<i8> = name_bytes.iter().map(|&b| b as i8).collect();
        ifr.ifr_name[..name_i8.len()].copy_from_slice(&name_i8);

        ifr.ifr_ifru.ifru_flags = (IFF_UP | IFF_RUNNING) as i16;

        let ret = unsafe { ioctl(sock_fd, SIOCSIFFLAGS, &ifr) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
}

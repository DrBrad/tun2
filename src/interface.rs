use std::{io, mem, ptr};
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::RawFd;
use crate::{Ifreq, DEST_MAC, ETHERTYPE_IPV4, AF_INET, AF_PACKET, ETH_P_ALL, SIOCGIFHWADDR, SOCK_DGRAM, SOCK_RAW, SIOCGIFADDR, sockaddr_ll, ifreq, syscall, SYS_SENDTO, SYS_SOCKET, SYS_IOCTL, IFNAMSIZ, SYS_READ, SYS_CLOSE};
use crate::utils::ip_utils::compute_checksum;



#[derive(Clone)]
pub struct Interface {
    interface: String,
    interface_index: i32,
    source_mac: [u8; 6],
    source_ip: Ipv4Addr,
    fd: RawFd
}

impl Interface {

    pub fn new(interface: &str) -> io::Result<Self> {
        let fd = unsafe { syscall(SYS_SOCKET, AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as i32) };
        //let fd = unsafe { socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as i32) };
        //let fd = unsafe { socket(AF_PACKET, SOCK_RAW, ETH_P_ALL.to_be()) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let interface_index = get_interface_index(interface)?;
        let source_mac = get_mac_address(interface)?;
        let source_ip = get_ip_address(interface)?;

        Ok(Self {
            interface: interface.to_string(),
            interface_index,
            source_mac,
            source_ip,
            fd
        })
    }

    pub fn read(&self) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; 4096];
        let len = unsafe { syscall(SYS_READ, self.fd, buffer.as_mut_ptr() as *mut _, buffer.len()) };
        if len > 0 {
            buffer.truncate(len as usize);
            return Ok(buffer);
        }

        Err(io::Error::last_os_error())
    }

    pub fn write(&self, packet: &[u8]) -> io::Result<()> {
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
            syscall(
                SYS_SENDTO,
                self.fd,
                packet.as_ptr() as *const _,
                packet.len(),
                0,  // flags
                &sll as *const _ as *const _,
                mem::size_of::<sockaddr_ll>() as u32,
            )
        };


        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
}

fn get_interface_index(interface: &str) -> io::Result<i32> {
    let fd = unsafe { syscall(SYS_SOCKET, AF_PACKET, SOCK_RAW, ETH_P_ALL.to_be()) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ifr: ifreq = unsafe { mem::zeroed() };
    let name_bytes = interface.as_bytes();
    let name_i8: Vec<i8> = name_bytes.iter().map(|&b| b as i8).collect();
    ifr.ifr_name[..name_i8.len()].copy_from_slice(&name_i8);

    let ret = unsafe { syscall(SYS_IOCTL, fd, 0x8933, &mut ifr as *mut _) }; // SIOCGIFINDEX
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    unsafe { syscall(SYS_CLOSE, fd) };

    Ok(unsafe { ifr.ifr_ifru.ifru_ifindex })
}

fn get_mac_address(interface: &str) -> io::Result<[u8; 6]> {
    let fd = unsafe { syscall(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ifr: ifreq = unsafe { mem::zeroed() };

    // Convert &str to [i8; IFNAMSIZ] (interface name)
    let mut name_bytes = [0i8; IFNAMSIZ];
    for (i, &b) in interface.as_bytes().iter().enumerate() {
        name_bytes[i] = b as i8;
    }
    ifr.ifr_name.copy_from_slice(&name_bytes);

    let ret = unsafe { syscall(SYS_IOCTL, fd, SIOCGIFHWADDR, &mut ifr) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    unsafe { syscall(SYS_CLOSE, fd) };

    let mac = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data };
    Ok([mac[0] as u8, mac[1] as u8, mac[2] as u8, mac[3] as u8, mac[4] as u8, mac[5] as u8])
}


fn get_ip_address(interface: &str) -> io::Result<Ipv4Addr> {
    let fd = unsafe { syscall(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ifr: Ifreq = unsafe { mem::zeroed() };
    let cstr = CString::new(interface).unwrap();
    let name = cstr.as_bytes_with_nul();

    // Copy the interface name to the ifr_name field of Ifreq
    unsafe {
        ptr::copy_nonoverlapping(
            name.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8, // Cast to *mut u8 here
            name.len(),
        );
    }

    let res = unsafe { syscall(SYS_IOCTL, fd, SIOCGIFADDR, &mut ifr as *mut Ifreq) };

    if res < 0 {
        unsafe { syscall(SYS_CLOSE, fd) };
        return Err(io::Error::last_os_error());
    }

    // Extract the IP address from the sockaddr_in structure
    let sin_addr = ifr.ifr_addr.sin_addr;

    unsafe { syscall(SYS_CLOSE, fd) };

    Ok(Ipv4Addr::new(
        (sin_addr & 0xFF) as u8,
        ((sin_addr >> 8) & 0xFF) as u8,
        ((sin_addr >> 16) & 0xFF) as u8,
        ((sin_addr >> 24) & 0xFF) as u8,
    ))
}

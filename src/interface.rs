use std::{io, mem};
use std::net::Ipv4Addr;
use std::os::fd::RawFd;
use pcap::packet::layers::ethernet_frame::inter::ethernet_address::EthernetAddress;
use crate::{AF_PACKET, ETH_P_ALL, SOCK_RAW, sockaddr_ll, syscall, SYS_SENDTO, SYS_SOCKET, SYS_READ};
use crate::utils::interface_utils::{get_interface_index, get_address, get_mac};

#[derive(Clone)]
pub struct Interface {
    interface: String,
    interface_index: i32,
    fd: RawFd
}

impl Interface {

    pub fn new(interface: &str) -> io::Result<Self> {
        let fd = unsafe { syscall(SYS_SOCKET, AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as i32) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let interface_index = get_interface_index(interface)?;

        Ok(Self {
            interface: interface.to_string(),
            interface_index,
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

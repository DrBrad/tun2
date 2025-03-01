use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::{io, mem};
use std::os::fd::FromRawFd;
use crate::{IFF_NO_PI, ifreq, syscall, SYS_IOCTL, SYS_READ, SYS_WRITE, SYS_DUP, IFF_TAP, DEFAULT_NET_MASK, DEFAULT_ADDRESS, DEFAULT_GATEWAY};
use crate::utils::interface_utils::{add_default_route, bring_up, set_address};

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

        set_address(name, DEFAULT_ADDRESS, DEFAULT_NET_MASK)?;
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

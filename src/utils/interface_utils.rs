use std::{io, mem, ptr};
use std::ffi::CString;
use std::net::Ipv4Addr;
use std::ptr::copy_nonoverlapping;
use libc::{rtentry, INADDR_ANY, SIOCADDRT};
use crate::{ifreq, sockaddr_in, syscall, AF_INET, IFF_RUNNING, IFF_UP, SIOCSIFADDR, SIOCSIFFLAGS, SOCK_DGRAM, SYS_IOCTL, SYS_SOCKET};

pub fn set_ip(interface: &str, ip: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
    let fd = unsafe { syscall(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 {
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
    sockaddr.sin_addr = u32::from(ip).to_be();//ip.parse::<Ipv4Addr>().unwrap().into();

    unsafe {
        let addr_ptr = &sockaddr as *const _ as *const u8;
        copy_nonoverlapping(addr_ptr, &mut ifr.ifr_ifru as *mut _ as *mut u8, mem::size_of::<sockaddr_in>());
    }

    let ret = unsafe { syscall(SYS_IOCTL, fd, SIOCSIFADDR, &ifr) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }







    // Convert netmask to sockaddr_in (for netmask)
    let mut sockaddr_mask: libc::sockaddr_in = unsafe { mem::zeroed() };
    sockaddr_mask.sin_family = AF_INET as u16;
    sockaddr_mask.sin_addr.s_addr = u32::from(netmask).to_be();

    unsafe {
        let addr_ptr = &sockaddr_mask as *const _ as *const u8;
        copy_nonoverlapping(addr_ptr, &mut ifr.ifr_ifru as *mut _ as *mut u8, mem::size_of::<sockaddr_in>());
    }

    // Set the netmask
    let ret = unsafe { syscall(SYS_IOCTL, fd, libc::SIOCSIFNETMASK, &ifr) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // Close the socket
    unsafe { libc::close(fd) };

    Ok(())
}


pub fn add_default_route(interface: &str, gateway: Ipv4Addr) -> io::Result<()> {
    let fd = unsafe { syscall(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Prepare the rtentry structure
    let mut rt: rtentry = unsafe { mem::zeroed() };

    // Set the gateway address (rt_gateway)
    let mut sockinfo: libc::sockaddr_in = unsafe { mem::zeroed() };
    sockinfo.sin_family = libc::AF_INET as u16;
    sockinfo.sin_addr.s_addr = u32::from(gateway).to_be(); // Convert the IP to network byte order
    unsafe {
        ptr::write(&mut rt.rt_gateway as *mut _ as *mut libc::sockaddr_in, sockinfo);
    }

    // Set the destination address (rt_dst)
    sockinfo.sin_addr.s_addr = INADDR_ANY; // 0.0.0.0
    unsafe {
        ptr::write(&mut rt.rt_dst as *mut _ as *mut libc::sockaddr_in, sockinfo);
    }

    // Set the genmask (rt_genmask)
    sockinfo.sin_addr.s_addr = INADDR_ANY; // 0.0.0.0
    unsafe {
        ptr::write(&mut rt.rt_genmask as *mut _ as *mut libc::sockaddr_in, sockinfo);
    }

    // Set flags for the route
    rt.rt_flags = libc::RTF_UP | libc::RTF_GATEWAY;

    // Set the device name (e.g., "eth0")
    let c_str = CString::new(interface).unwrap();
    rt.rt_dev = c_str.into_raw();

    // Add the route using ioctl
    let result = unsafe { syscall(SYS_IOCTL, fd, SIOCADDRT, &rt) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    // Close the socket
    unsafe { libc::close(fd) };

    Ok(())
}

pub fn bring_up(interface: &str) -> io::Result<()> {
    let fd = unsafe { syscall(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ifr: ifreq = unsafe { mem::zeroed() };
    let name_bytes = interface.as_bytes();
    let name_i8: Vec<i8> = name_bytes.iter().map(|&b| b as i8).collect();
    ifr.ifr_name[..name_i8.len()].copy_from_slice(&name_i8);

    ifr.ifr_ifru.ifru_flags = (IFF_UP | IFF_RUNNING) as i16;

    let ret = unsafe { syscall(SYS_IOCTL, fd, SIOCSIFFLAGS, &ifr) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // Close the socket
    unsafe { libc::close(fd) };

    Ok(())
}

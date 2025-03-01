use std::{io, mem, ptr};
use std::ffi::CString;
use std::net::Ipv4Addr;
use std::ptr::copy_nonoverlapping;
use pcap::packet::layers::ethernet_frame::inter::ethernet_address::EthernetAddress;
use crate::{ifreq, rtentry, sockaddr, sockaddr_in, syscall, Ifreq, AF_INET, AF_PACKET, ETH_P_ALL, IFF_RUNNING, IFF_UP, IFNAMSIZ, INADDR_ANY, RTF_GATEWAY, RTF_UP, SIOCADDRT, SIOCGIFADDR, SIOCGIFHWADDR, SIOCGIFINDEX, SIOCSIFADDR, SIOCSIFFLAGS, SIOCSIFHWADDR, SIOCSIFNETMASK, SOCK_DGRAM, SOCK_RAW, SYS_CLOSE, SYS_IOCTL, SYS_SOCKET};

pub fn set_address(interface: &str, address: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
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
    sockaddr.sin_addr = u32::from(address).to_be();//ip.parse::<Ipv4Addr>().unwrap().into();

    unsafe {
        let addr_ptr = &sockaddr as *const _ as *const u8;
        copy_nonoverlapping(addr_ptr, &mut ifr.ifr_ifru as *mut _ as *mut u8, mem::size_of::<sockaddr_in>());
    }

    let ret = unsafe { syscall(SYS_IOCTL, fd, SIOCSIFADDR, &ifr) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // Convert netmask to sockaddr_in (for netmask)
    let mut sockaddr_mask: sockaddr_in = unsafe { mem::zeroed() };
    sockaddr_mask.sin_family = AF_INET as u16;
    sockaddr_mask.sin_addr = u32::from(netmask).to_be();

    unsafe {
        let addr_ptr = &sockaddr_mask as *const _ as *const u8;
        copy_nonoverlapping(addr_ptr, &mut ifr.ifr_ifru as *mut _ as *mut u8, mem::size_of::<sockaddr_in>());
    }

    // Set the netmask
    let ret = unsafe { syscall(SYS_IOCTL, fd, SIOCSIFNETMASK, &ifr) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    unsafe { syscall(SYS_CLOSE, fd) };

    Ok(())
}

pub fn get_address(interface: &str) -> io::Result<Ipv4Addr> {
    let fd = unsafe { syscall(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ifr: Ifreq = unsafe { mem::zeroed() };

    // Convert &str to [i8; IFNAMSIZ] (interface name)
    let mut name_bytes = [0i8; IFNAMSIZ];
    for (i, &b) in interface.as_bytes().iter().enumerate() {
        name_bytes[i] = b as i8;
    }
    ifr.ifr_name.copy_from_slice(&name_bytes);

    let res = unsafe { syscall(SYS_IOCTL, fd, SIOCGIFADDR, &mut ifr) };

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

pub fn add_default_route(interface: &str, gateway: Ipv4Addr) -> io::Result<()> {
    let fd = unsafe { syscall(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Prepare the rtentry structure
    let mut rt: rtentry = unsafe { mem::zeroed() };

    // Set the gateway address (rt_gateway)
    let mut sockinfo: sockaddr_in = unsafe { mem::zeroed() };
    sockinfo.sin_family = AF_INET as u16;
    sockinfo.sin_addr = u32::from(gateway).to_be(); // Convert the IP to network byte order
    unsafe {
        ptr::write(&mut rt.rt_gateway as *mut _ as *mut sockaddr_in, sockinfo);
    }

    // Set the destination address (rt_dst)
    sockinfo.sin_addr = INADDR_ANY; // 0.0.0.0
    unsafe {
        ptr::write(&mut rt.rt_dst as *mut _ as *mut sockaddr_in, sockinfo);
    }

    // Set the genmask (rt_genmask)
    sockinfo.sin_addr = INADDR_ANY; // 0.0.0.0
    unsafe {
        ptr::write(&mut rt.rt_genmask as *mut _ as *mut sockaddr_in, sockinfo);
    }

    // Set flags for the route
    rt.rt_flags = RTF_UP | RTF_GATEWAY;

    // Set the device name (e.g., "eth0")
    let c_str = CString::new(interface).unwrap();
    rt.rt_dev = c_str.into_raw();

    // Add the route using ioctl
    let result = unsafe { syscall(SYS_IOCTL, fd, SIOCADDRT, &rt) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    unsafe { syscall(SYS_CLOSE, fd) };

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

    unsafe { syscall(SYS_CLOSE, fd) };

    Ok(())
}

pub fn get_interface_index(interface: &str) -> io::Result<i32> {
    let fd = unsafe { syscall(SYS_SOCKET, AF_PACKET, SOCK_RAW, ETH_P_ALL.to_be()) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ifr: ifreq = unsafe { mem::zeroed() };
    let name_bytes = interface.as_bytes();
    let name_i8: Vec<i8> = name_bytes.iter().map(|&b| b as i8).collect();
    ifr.ifr_name[..name_i8.len()].copy_from_slice(&name_i8);

    let ret = unsafe { syscall(SYS_IOCTL, fd, SIOCGIFINDEX, &mut ifr as *mut _) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    unsafe { syscall(SYS_CLOSE, fd) };

    Ok(unsafe { ifr.ifr_ifru.ifru_ifindex })
}

pub fn set_mac(interface: &str, mac: EthernetAddress) -> io::Result<()> {
    let fd = unsafe { syscall(SYS_SOCKET, 2, 1, 0) }; // AF_INET, SOCK_DGRAM, 0
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ifr: ifreq = unsafe { mem::zeroed() };

    // Set the interface name
    let name_bytes = interface.as_bytes();
    let name_i8: Vec<i8> = name_bytes.iter().map(|&b| b as i8).collect();
    ifr.ifr_name[..name_i8.len()].copy_from_slice(&name_i8);

    // Set the MAC address in the sockaddr struct inside ifreq
    let mut sockaddr = sockaddr {
        sa_family: 1, // AF_INET
        sa_data: [0; 14],
    };
    for (i, &byte) in mac.to_bytes().iter().enumerate() {
        sockaddr.sa_data[i] = byte as i8;
    }

    // Set the sockaddr in ifreq
    unsafe {
        ifr.ifr_ifru.ifru_hwaddr = sockaddr;
    }

    // Perform the ioctl system call to set the MAC address
    let ret = unsafe { syscall(SYS_IOCTL, fd, SIOCSIFHWADDR, &ifr) };
    if ret < 0 {
        unsafe { syscall(SYS_CLOSE, fd) };
        return Err(io::Error::last_os_error());
    }

    // Close the socket
    unsafe { syscall(SYS_CLOSE, fd) };

    Ok(())
}

pub fn get_mac(interface: &str) -> io::Result<EthernetAddress> {
    let fd = unsafe { syscall(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ifr: ifreq = unsafe { mem::zeroed() };
    let name_bytes = interface.as_bytes();
    let name_i8: Vec<i8> = name_bytes.iter().map(|&b| b as i8).collect();
    ifr.ifr_name[..name_i8.len()].copy_from_slice(&name_i8);

    let ret = unsafe { syscall(SYS_IOCTL, fd, SIOCGIFHWADDR, &mut ifr) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    unsafe { syscall(SYS_CLOSE, fd) };

    let mac = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data };
    Ok(EthernetAddress::new(mac[0] as u8, mac[1] as u8, mac[2] as u8, mac[3] as u8, mac[4] as u8, mac[5] as u8))
}

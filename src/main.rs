use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::net::UdpSocket;
use std::mem;
use libc::{c_int, c_short, c_ulong, ifreq, ioctl, IFF_TUN, IFF_NO_PI, O_RDWR, SOCK_RAW, AF_PACKET, ETH_P_ALL, sockaddr_ll, socket, sendto};

const TUN_DEVICE: &str = "/dev/net/tun";
const DEST_INTERFACE: &str = "wlp7s0"; // Change this to your real interface

/*
sudo ip addr add 10.0.0.1/24 dev tun0
sudo ip link set dev tun0 up
sudo ip route add default via 10.0.0.1 dev tun0

ping -I tun0 8.8.8.8
*/

fn create_tun_interface(name: &str) -> std::io::Result<File> {
    let file = File::options().read(true).write(true).open(TUN_DEVICE)?;

    let fd = file.as_raw_fd();
    let mut ifr: ifreq = unsafe { mem::zeroed() };

    let name_bytes = name.as_bytes();
    let name_i8: Vec<i8> = name_bytes.iter().map(|&b| b as i8).collect();
    ifr.ifr_name[..name_i8.len()].copy_from_slice(&name_i8);

    ifr.ifr_ifru.ifru_flags = (IFF_TUN | IFF_NO_PI) as c_short;

    let ret = unsafe { ioctl(fd, 0x400454ca, &mut ifr as *mut _) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(file)
}

fn read_from_tun(file: &File) -> std::io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; 4096];
    let len = unsafe { libc::read(file.as_raw_fd(), buffer.as_mut_ptr() as *mut _, buffer.len()) };

    if len < 0 {
        return Err(std::io::Error::last_os_error());
    }

    buffer.truncate(len as usize);
    Ok(buffer)
}

fn write_to_interface(socket_fd: RawFd, packet: &[u8], dest_ifindex: i32) -> std::io::Result<()> {
    let mut sockaddr: sockaddr_ll = unsafe { mem::zeroed() };
    sockaddr.sll_family = AF_PACKET as u16;
    sockaddr.sll_ifindex = dest_ifindex;
    sockaddr.sll_protocol = (ETH_P_ALL as u16).to_be();

    let res = unsafe {
        sendto(
            socket_fd,
            packet.as_ptr() as *const _,
            packet.len(),
            0,
            &sockaddr as *const sockaddr_ll as *const _,
            mem::size_of::<sockaddr_ll>() as u32,
        )
    };

    if res < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

















fn get_interface_index(interface: &str) -> std::io::Result<i32> {
    let socket_fd = unsafe { socket(AF_PACKET, SOCK_RAW, ETH_P_ALL.to_be() as i32) };
    if socket_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut ifr: ifreq = unsafe { mem::zeroed() };
    let name_bytes = interface.as_bytes();
    let name_i8: Vec<i8> = name_bytes.iter().map(|&b| b as i8).collect();
    ifr.ifr_name[..name_i8.len()].copy_from_slice(&name_i8);

    let ret = unsafe { ioctl(socket_fd, 0x8933, &mut ifr as *mut _) }; // SIOCGIFINDEX
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    unsafe { libc::close(socket_fd) };

    Ok(unsafe { ifr.ifr_ifru.ifru_ifindex })
}

fn main() -> std::io::Result<()> {
    let tun_file = create_tun_interface("tun0")?;
    println!("TUN interface created: tun0");

    let dest_ifindex = get_interface_index(DEST_INTERFACE)?;
    println!("Forwarding packets to interface index: {}", dest_ifindex);

    let socket_fd = unsafe { socket(AF_PACKET, SOCK_RAW, ETH_P_ALL.to_be() as i32) };
    if socket_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    loop {
        let packet = read_from_tun(&tun_file)?;
        println!("Received packet: {:?}", &packet[..20]);

        write_to_interface(socket_fd, &packet, dest_ifindex)?;
        println!("Forwarded packet to {}", DEST_INTERFACE);
    }
}

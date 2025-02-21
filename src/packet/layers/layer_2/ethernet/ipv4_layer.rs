use std::any::Any;
use std::net::Ipv4Addr;
use crate::packet::layers::inter::layer::Layer;
use crate::packet::layers::layer_2::ethernet::inter::protocols::Protocols;

#[derive(Clone, Debug)]
pub struct IPv4Layer {
    version: u8,
    ihl: u8,
    tos: u8,
    total_length: u16,
    identification: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    protocol: Protocols,
    checksum: u16,
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr
}

impl IPv4Layer {

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 20 {
            return None;
        }

        let version_ihl = buf[0];
        let version = version_ihl >> 4;
        let ihl = version_ihl & 0x0F;

        Some(Self {
            version,
            ihl,
            tos: buf[1],
            total_length: u16::from_be_bytes([buf[2], buf[3]]),
            identification: u16::from_be_bytes([buf[4], buf[5]]),
            flags: buf[6] >> 5,
            fragment_offset: u16::from_be_bytes([buf[6] & 0x1F, buf[7]]),
            ttl: buf[8],
            protocol: Protocols::get_protocol_from_code(buf[9]).unwrap(),
            checksum: u16::from_be_bytes([buf[10], buf[11]]),
            source_ip: Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]),
            destination_ip: Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19])
        })
    }

    pub fn get_version(&self) -> u8 {
        self.version
    }

    pub fn get_ihl(&self) -> u8 {
        self.ihl
    }

    pub fn get_tos(&self) -> u8 {
        self.ihl
    }

    pub fn get_total_length(&self) -> u16 {
        self.total_length
    }

    pub fn get_identification(&self) -> u16 {
        self.identification
    }

    pub fn get_flags(&self) -> u8 {
        self.flags
    }

    pub fn get_fragment_offset(&self) -> u16 {
        self.fragment_offset
    }

    pub fn get_ttl(&self) -> u8 {
        self.ttl
    }

    pub fn get_protocol(&self) -> Protocols {
        self.protocol
    }

    pub fn get_checksum(&self) -> u16 {
        self.checksum
    }

    pub fn get_source_ip(&self) -> &Ipv4Addr {
        &self.source_ip
    }

    pub fn get_destination_ip(&self) -> &Ipv4Addr {
        &self.destination_ip
    }
}

impl Layer for IPv4Layer {

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0; self.len()];

        buf[0] = (self.version << 4) | (self.ihl & 0x0F);
        buf[1] = self.tos;
        buf.splice(2..4, self.total_length.to_be_bytes());
        buf.splice(4..6, self.identification.to_be_bytes());
        buf[6] = (self.flags << 5) | ((self.fragment_offset >> 8) as u8 & 0x1F);
        buf[7] = (self.fragment_offset & 0xFF) as u8;
        buf[8] = self.ttl;
        buf[9] = self.protocol.get_code();
        buf.splice(10..12, self.checksum.to_be_bytes());
        buf.splice(12..16, self.source_ip.octets());
        buf.splice(16..20, self.destination_ip.octets());

        buf
    }

    fn len(&self) -> usize {
        20
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn dyn_clone(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }
}

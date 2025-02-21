use std::any::Any;
use std::net::Ipv6Addr;
use crate::packet::layers::inter::layer::Layer;
use crate::packet::layers::layer_2::ethernet::inter::protocols::Protocols;

#[derive(Clone, Debug)]
pub struct IPv6Layer {
    version: u8,
    traffic_class: u8,
    flow_label: u32,
    payload_length: u16,
    next_header: Protocols,
    hop_limit: u8,
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr
}

impl IPv6Layer {

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 40 {
            return None;
        }

        Some(Self {
            version: (buf[0] >> 4) & 0x0F,
            traffic_class: ((buf[0] & 0x0F) << 4) | (buf[1] >> 4),
            flow_label: ((buf[1] as u32 & 0x0F) << 16) | ((buf[2] as u32) << 8) | (buf[3] as u32),
            payload_length: u16::from_be_bytes([buf[4], buf[5]]),
            next_header: Protocols::get_protocol_from_code(buf[6]).unwrap(),
            hop_limit: buf[7],
            source_ip: Ipv6Addr::from(<[u8; 16]>::try_from(&buf[8..24]).unwrap()),
            destination_ip: Ipv6Addr::from(<[u8; 16]>::try_from(&buf[24..40]).unwrap())
        })
    }

    pub fn get_version(&self) -> u8 {
        self.version
    }

    pub fn get_traffic_class(&self) -> u8 {
        self.traffic_class
    }

    pub fn get_flow_label(&self) -> u32 {
        self.flow_label
    }

    pub fn get_payload_length(&self) -> u16 {
        self.payload_length
    }

    pub fn get_next_header(&self) -> Protocols {
        self.next_header
    }

    pub fn get_hop_limit(&self) -> u8 {
        self.hop_limit
    }

    pub fn get_source_ip(&self) -> &Ipv6Addr {
        &self.source_ip
    }

    pub fn get_destination_ip(&self) -> &Ipv6Addr {
        &self.destination_ip
    }
}

impl Layer for IPv6Layer {

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0; self.len()];

        buf[0] = (self.version << 4) | ((self.traffic_class >> 4) & 0x0F);
        buf[1] = ((self.traffic_class & 0x0F) << 4) | ((self.flow_label >> 16) as u8 & 0x0F);
        buf[2] = ((self.flow_label >> 8) & 0xFF) as u8;
        buf[3] = (self.flow_label & 0xFF) as u8;
        buf.splice(4..6, self.payload_length.to_be_bytes());
        buf[6] = self.next_header.get_code();
        buf[7] = self.hop_limit;
        buf.splice(8..24, self.source_ip.octets());
        buf.splice(24..40, self.destination_ip.octets());

        buf
    }

    fn len(&self) -> usize {
        40
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

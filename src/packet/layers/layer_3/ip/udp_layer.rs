use std::any::Any;
use crate::packet::layers::inter::layer::Layer;

#[derive(Clone, Debug)]
pub struct UdpLayer {
    source_port: u16,
    destination_port: u16,
    length: u16,
    checksum: u16
}

impl UdpLayer {

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }

        Some(Self {
            source_port: u16::from_be_bytes([buf[0], buf[1]]),
            destination_port: u16::from_be_bytes([buf[2], buf[3]]),
            length: u16::from_be_bytes([buf[4], buf[5]]),
            checksum: u16::from_be_bytes([buf[6], buf[7]])
        })
    }

    pub fn get_source_port(&self) -> u16 {
        self.source_port
    }

    pub fn get_destination_port(&self) -> u16 {
        self.destination_port
    }

    pub fn get_length(&self) -> u16 {
        self.length
    }

    pub fn get_checksum(&self) -> u16 {
        self.checksum
    }
}

impl Layer for UdpLayer {

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0; self.len()];

        buf.splice(0..2, self.source_port.to_be_bytes());
        buf.splice(2..4, self.destination_port.to_be_bytes());
        buf.splice(4..6, self.length.to_be_bytes());
        buf.splice(6..8, self.checksum.to_be_bytes());

        buf
    }

    fn len(&self) -> usize {
        14
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

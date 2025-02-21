use std::any::Any;
use crate::packet::layers::inter::layer::Layer;
use crate::packet::layers::layer_1::inter::ethernet_address::EthernetAddress;
use crate::packet::layers::layer_1::inter::types::Types;

#[derive(Clone, Debug)]
pub struct EthernetLayer {
    destination: EthernetAddress,
    source: EthernetAddress,
    _type: Types,
    //data: Vec<u8>
}

impl EthernetLayer {

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 14 {
            return None;
        }

        //let _type = Types::get_type_from_code(u16::from_be_bytes([buf[12], buf[13]])).unwrap();

        /*
        let data = match _type {
            Types::Arp => {
                buf[14..].to_vec()
            }
            Types::Broadcast => {
                buf[14..].to_vec()
            }
            _ => Vec::new()
        };
        */

        Some(Self {
            destination: EthernetAddress::new([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]]),
            source: EthernetAddress::new([buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]]),
            _type: Types::get_type_from_code(u16::from_be_bytes([buf[12], buf[13]])).unwrap()
        })
    }

    pub fn get_destination(&self) -> &EthernetAddress {
        &self.destination
    }

    pub fn get_source(&self) -> &EthernetAddress {
        &self.source
    }

    pub fn get_type(&self) -> Types {
        self._type
    }
}

impl Layer for EthernetLayer {

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0; self.len()];
        buf.splice(0..6, self.destination.to_bytes());
        buf.splice(6..12, self.source.to_bytes());
        buf.splice(12..14, self._type.get_code().to_be_bytes());

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

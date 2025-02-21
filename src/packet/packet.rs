use std::time::{SystemTime, UNIX_EPOCH};
use crate::packet::inter::interfaces::Interfaces;
use crate::packet::layers::inter::layer::Layer;
use crate::packet::layers::layer_1::ethernet_layer::EthernetLayer;
use crate::packet::layers::layer_1::inter::types::Types;
use crate::packet::layers::layer_2::ethernet::inter::protocols::Protocols;
use crate::packet::layers::layer_2::ethernet::ipv4_layer::IPv4Layer;
use crate::packet::layers::layer_2::ethernet::ipv6_layer::IPv6Layer;
use crate::packet::layers::layer_3::ip::tcp_layer::TcpLayer;
use crate::packet::layers::layer_3::ip::udp_layer::UdpLayer;

#[derive(Debug, Clone)]
pub struct Packet {
    interface: Interfaces,
    layers: Vec<Box<dyn Layer>>,
    frame_time: u128,
    length: u32
}

impl Packet {

    pub fn new(interface: Interfaces, frame_time: u128, length: u32) -> Self {
        Self {
            interface,
            layers: Vec::new(),
            frame_time,
            length
        }
    }

    pub fn get_interface(&self) -> &Interfaces {
        &self.interface
    }

    pub fn add_layer(&mut self, layer: Box<dyn Layer>) {
        self.layers.push(layer);
    }

    pub fn get_layer(&self, index: usize) -> Option<&Box<dyn Layer>> {
        self.layers.get(index)
    }

    pub fn get_layers(&self) -> &Vec<Box<dyn Layer>> {
        &self.layers
    }

    pub fn get_total_layers(&self) -> usize {
        self.layers.len()
    }

    pub fn get_frame_time(&self) -> u128 {
        self.frame_time
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.length as usize];
        let mut off = 0;

        for layer in &self.layers {
            let encoded_layer = layer.to_bytes();
            buf.splice(off..off + layer.len(), encoded_layer);
            off += layer.len();
        }

        buf
    }

    pub fn len(&self) -> u32 {
        self.length
    }
}

pub fn decode_packet(interface: Interfaces, data: &[u8]) -> Packet {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis();

    let mut frame = Packet::new(interface, now, data.len() as u32);

    match frame.get_interface() {
        Interfaces::Ethernet => {
            let ethernet_layer = EthernetLayer::from_bytes(&data).expect("Failed to parse Ethernet frame");
            frame.add_layer(ethernet_layer.dyn_clone());
            let mut off = ethernet_layer.len();

            match ethernet_layer.get_type() {
                Types::IPv4 => {
                    let ipv4_layer = IPv4Layer::from_bytes(&data[off..]).expect("Failed to parse IPv4 frame");
                    frame.add_layer(ipv4_layer.dyn_clone());
                    off += ipv4_layer.len();

                    match ipv4_layer.get_protocol() {
                        Protocols::HopByHop => {}
                        Protocols::Icmp => {}
                        Protocols::Igmp => {}
                        Protocols::Tcp => {
                            let tcp_layer = TcpLayer::from_bytes(&data[off..]).expect("Failed to parse TCP frame");
                            frame.add_layer(tcp_layer.dyn_clone());
                            off += tcp_layer.len();
                        }
                        Protocols::Udp => {
                            let udp_layer = UdpLayer::from_bytes(&data[off..]).expect("Failed to parse UDP frame");
                            frame.add_layer(udp_layer.dyn_clone());
                            off += udp_layer.len();
                        }
                        Protocols::Ipv6 => {}
                        Protocols::Icmpv6 => {}
                        Protocols::Gre => {}
                        Protocols::Ospf => {}
                        Protocols::Sps => {}
                    }




                }
                Types::Arp => {}
                Types::IPv6 => {
                    let ipv6_layer = IPv6Layer::from_bytes(&data[off..]).expect("Failed to parse IPv6 frame");
                    frame.add_layer(ipv6_layer.dyn_clone());
                    off += ipv6_layer.len();

                    match ipv6_layer.get_next_header() {
                        Protocols::HopByHop => {}
                        Protocols::Icmp => {}
                        Protocols::Igmp => {}
                        Protocols::Tcp => {
                            let tcp_layer = TcpLayer::from_bytes(&data[off..]).expect("Failed to parse TCP frame");
                            frame.add_layer(tcp_layer.dyn_clone());
                            off += tcp_layer.len();
                        }
                        Protocols::Udp => {
                            let udp_layer = UdpLayer::from_bytes(&data[off..]).expect("Failed to parse UDP frame");
                            frame.add_layer(udp_layer.dyn_clone());
                            off += udp_layer.len();
                        }
                        Protocols::Ipv6 => {}
                        Protocols::Icmpv6 => {}
                        Protocols::Gre => {}
                        Protocols::Ospf => {}
                        Protocols::Sps => {}
                    }
                }
                Types::Broadcast => {}
            }





        }
        Interfaces::WiFi => {}
        Interfaces::Bluetooth => {}
    }

    frame
}

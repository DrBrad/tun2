#[derive(Clone, Debug)]
pub struct EthernetAddress {
    address: [u8; 6]
}

impl EthernetAddress {

    pub fn new(address: [u8; 6]) -> EthernetAddress {
        Self {
            address
        }
    }

    pub fn to_bytes(&self) -> [u8; 6] {
        self.address
    }

    pub fn to_string(&self) -> String {
        self.address.iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join(":")
    }
}


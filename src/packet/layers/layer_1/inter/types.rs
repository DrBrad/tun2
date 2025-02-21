#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum Types {
    IPv4,
    Arp,
    IPv6,
    Broadcast
}

impl Types {

    pub fn get_type_from_code(code: u16) -> Result<Self, String> {
        for c in [Self::IPv4, Self::Arp, Self::IPv6, Self::Broadcast] {
            if c.get_code() == code {
                return Ok(c);
            }
        }

        Err(format!("Couldn't find for code: {}", code))
    }

    pub fn get_code(&self) -> u16 {
        match self {
            Self::IPv4 => 2048,
            Self::Arp => 2054,
            Self::IPv6 => 34525,
            Self::Broadcast => 34969
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            Self::IPv4 => "IPv4",
            Self::Arp => "ARP",
            Self::IPv6 => "IPv6",
            Self::Broadcast => "Broadcast"
        }.to_string()
    }
}

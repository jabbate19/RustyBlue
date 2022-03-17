use std::fmt;

pub enum Layer3Protocol {
    IPv4,
    IPv6,
    ARP,
    Unknown
}

impl fmt::Display for Layer3Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Layer3Protocol::IPv4 => write!(f, "IPv4"),
            Layer3Protocol::IPv6 => write!(f, "IPv6"),
            Layer3Protocol::ARP => write!(f, "ARP"),
            Layer3Protocol::Unknown => write!(f, "???"),
        }
    }
}

pub enum Layer4Protocol {
    TCP,
    UDP,
    ICMP,
    ICMPv6,
    ARP,
    Unknown
}

impl fmt::Display for Layer4Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Layer4Protocol::TCP => write!(f, "TCP"),
            Layer4Protocol::UDP => write!(f, "UDP"),
            Layer4Protocol::ICMP => write!(f, "ICMP"),
            Layer4Protocol::ICMPv6 => write!(f, "ICMPv6"),
            Layer4Protocol::ARP => write!(f, "ARP"),
            Layer4Protocol::Unknown => write!(f, "???"),
        }
    }
}
use std::fmt;

pub enum Layer3Protocol {
    IPv4,
    IPv6,
    Arp,
    Unknown,
}

impl fmt::Display for Layer3Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Layer3Protocol::IPv4 => write!(f, "IPv4"),
            Layer3Protocol::IPv6 => write!(f, "IPv6"),
            Layer3Protocol::Arp => write!(f, "ARP"),
            Layer3Protocol::Unknown => write!(f, "???"),
        }
    }
}

pub enum Layer4Protocol {
    Tcp,
    Udp,
    Icmp,
    ICMPv6,
    Arp,
    Unknown,
}

impl fmt::Display for Layer4Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Layer4Protocol::Tcp => write!(f, "TCP"),
            Layer4Protocol::Udp => write!(f, "UDP"),
            Layer4Protocol::Icmp => write!(f, "ICMP"),
            Layer4Protocol::ICMPv6 => write!(f, "ICMPv6"),
            Layer4Protocol::Arp => write!(f, "ARP"),
            Layer4Protocol::Unknown => write!(f, "???"),
        }
    }
}

use std::fmt;

pub enum Layer3 {
    IPv4,
    IPv6,
    Arp,
    Unknown(u16),
}

impl fmt::Display for Layer3 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Layer3::IPv4 => write!(f, "IPv4"),
            Layer3::IPv6 => write!(f, "IPv6"),
            Layer3::Arp => write!(f, "ARP"),
            Layer3::Unknown(x) => write!(f, "Unknown Layer 3! ({})", x),
        }
    }
}

impl From<u16> for Layer3 {
    fn from(n: u16) -> Self {
        match n {
            0x0800 => Self::IPv4,
            0x0806 => Self::Arp,
            0x86dd => Self::IPv6,
            unknown => Self::Unknown(unknown),
        }
    }
}

pub enum Layer4 {
    Tcp,
    Udp,
    Icmp,
    ICMPv6,
    Arp,
    IPv6HopByHop,
    Igmp,
    Unknown(u8),
}

impl fmt::Display for Layer4 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Layer4::Tcp => write!(f, "TCP"),
            Layer4::Udp => write!(f, "UDP"),
            Layer4::Icmp => write!(f, "ICMP"),
            Layer4::ICMPv6 => write!(f, "ICMPv6"),
            Layer4::Arp => write!(f, "ARP"),
            Layer4::Igmp => write!(f, "IGMP"),
            Layer4::IPv6HopByHop => write!(f, "IPv6HbH"),
            Layer4::Unknown(x) => write!(f, "Unknown Layer 3! ({})", x),
        }
    }
}

impl From<u8> for Layer4 {
    fn from(n: u8) -> Self {
        match n {
            0x00 => Self::IPv6HopByHop,
            0x02 => Self::Igmp,
            0x06 => Self::Tcp,
            0x11 => Self::Udp,
            0x01 => Self::Icmp,
            0x3A => Self::ICMPv6,
            unknown => Self::Unknown(unknown),
        }
    }
}

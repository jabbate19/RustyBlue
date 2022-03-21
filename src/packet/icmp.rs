use super::protocol::*;
use std::fmt;

pub struct Icmp<'a> {
    icmp_type: u8,
    icmp_code: u8,
    protocol: &'a Layer4,
}

impl<'a> Icmp<'a> {
    pub fn new(data: &[u8], protocol: &'a Layer4) -> Option<Icmp<'a>> {
        match protocol {
            Layer4::Icmp | Layer4::ICMPv6 => Some(Icmp {
                icmp_type: data[0],
                icmp_code: data[1],
                protocol,
            }),
            _ => None,
        }
    }
}

impl std::fmt::Display for Icmp<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.protocol {
            Layer4::Icmp => match self.icmp_type {
                0 => write!(f, "Echo Reply"),
                8 => write!(f, "Echo Request"),
                3 => write!(
                    f,
                    "Destination Unreachable ({})",
                    match self.icmp_code {
                        0 => "Net Unreachable",
                        1 => "Host Unreachable",
                        2 => "Protocol Unreachable",
                        3 => "Port Unreachable",
                        _ => "Other Reason",
                    }
                ),
                11 => write!(
                    f,
                    "Time Exceeded ({})",
                    match self.icmp_code {
                        0 => "Time to Live exceeded in Transit",
                        1 => "Fragment Reassembly Time Exceeded",
                        _ => "Other Reason",
                    }
                ),
                _ => write!(f, "Unknown ICMP Type"),
            },
            Layer4::ICMPv6 => match self.icmp_type {
                1 => write!(
                    f,
                    "Destination Unreachable ({})",
                    match self.icmp_code {
                        0 => "No Route to Destination",
                        1 => "Communication with Destination Administratively Prohibited",
                        2 => "Beyond Scope of Source Address",
                        3 => "Address Unreachable",
                        4 => "Port Unreachable",
                        5 => "Source Address Failed Ingress/Egress Policy",
                        6 => "Reject Route to Destination",
                        7 => "Error in Source Routing Header",
                        8 => "Headers too long",
                        _ => "Unknown Reason",
                    }
                ),
                2 => write!(f, "Packet Too Big"),
                3 => write!(f, "Time Exceeded"),
                128 => write!(f, "Echo Request"),
                129 => write!(f, "Echo Reply"),
                133 => write!(f, "Router Solicitation"),
                134 => write!(f, "Router Advertisement"),
                135 => write!(f, "Neighbor Solicitation"),
                136 => write!(f, "Neighbor Advertisement"),
                137 => write!(f, "Redirect Message"),
                138 => write!(f, "Router Renumbering"),
                _ => write!(f, "Unknown Code"),
            },
            _ => write!(f, "???"),
        }
    }
}

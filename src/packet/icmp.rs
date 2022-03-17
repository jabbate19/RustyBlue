use super::protocol::*;

pub struct ICMP<'a> {
    icmp_type: u8,
    icmp_code: u8,
    protocol: &'a Layer4Protocol,
}

impl<'a> ICMP<'a> {
    pub fn new(data: &[u8], protocol: &'a Layer4Protocol) -> Option<ICMP<'a>> {
        match protocol {
            Layer4Protocol::ICMP | Layer4Protocol::ICMPv6 => Some(ICMP{
                icmp_type: data[0],
                icmp_code: data[1],
                protocol: protocol,
            }),
            _ => None,
        }
    }

    pub fn to_string(&self) -> String {
        match self.protocol {
            Layer4Protocol::ICMP => match self.icmp_type {
                0 => String::from("Echo Reply"),
                8 => String::from("Echo Request"),
                3 => format!("Destination Unreachable ({})", match self.icmp_code {
                    0 => "Net Unreachable",
                    1 => "Host Unreachable",
                    2 => "Protocol Unreachable",
                    3 => "Port Unreachable",
                    _ => "Other Reason",
                }),
                11 => format!("Time Exceeded ({})", match self.icmp_code {
                    0 => "Time to Live exceeded in Transit",
                    1 => "Fragment Reassembly Time Exceeded",
                    _ => "Other Reason"
                }),
                _ => String::from("Unknown ICMP Type")
            },
            Layer4Protocol::ICMPv6 => match self.icmp_type {
                1 => format!("Destination Unreachable ({})", match self.icmp_code {
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
                }),
                2 => String::from("Packet Too Big"),
                3 => String::from("Time Exceeded"),
                128 => String::from("Echo Request"),
                129 => String::from("Echo Reply"),
                133 => String::from("Router Solicitation"),
                134 => String::from("Router Advertisement"),
                135 => String::from("Neighbor Solicitation"),
                136 => String::from("Neighbor Advertisement"),
                137 => String::from("Redirect Message"),
                138 => String::from("Router Renumbering"),
                _ => String::from("Unknown Code"),
            }
            _ => String::from("???"),
        }
    }
}
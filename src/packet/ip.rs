use super::arp::Arp;
use super::protocol::*;

pub struct IP<'a> {
    pub src: String,
    pub dst: String,
    pub protocol: Layer4Protocol,
    pub arp: Option<Arp>,
    pub payload: &'a [u8],
}

impl<'a> IP<'a> {
    pub fn new(data: &[u8], protocol: Layer3Protocol) -> Option<IP> {
        match protocol {
            Layer3Protocol::Arp => {
                let src = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
                let dst = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);
                Some(IP {
                    src: format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]),
                    dst: format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]),
                    protocol: Layer4Protocol::Arp,
                    arp: Arp::new(src, dst, data),
                    payload: &data[20..],
                })
            }
            Layer3Protocol::IPv4 => Some(IP {
                src: format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]),
                dst: format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]),
                protocol: IP::get_protocol(&data[9]),
                arp: None,
                payload: &data[20..],
            }),
            Layer3Protocol::IPv6 => Some(IP {
                src: IP::decimal_to_ipv6(data, 8),
                dst: IP::decimal_to_ipv6(data, 24),
                protocol: IP::get_protocol(&data[6]),
                arp: None,
                payload: &data[40..],
            }),
            _ => None,
        }
    }

    fn get_protocol(byte: &u8) -> Layer4Protocol {
        match byte {
            6 => Layer4Protocol::Tcp,
            17 => Layer4Protocol::Udp,
            1 => Layer4Protocol::Icmp,
            58 => Layer4Protocol::ICMPv6,
            _ => Layer4Protocol::Unknown,
        }
    }

    fn decimal_to_ipv6(data: &'a [u8], start_index: usize) -> String {
        let mut out = String::new();
        for i in (start_index..start_index + 16).step_by(2) {
            let a = format!("{:X?}", data[i]);
            let b = format!("{:X?}", data[i + 1]);
            if a.eq("0") {
                if b.eq("0") {
                    out.push_str("0:");
                } else {
                    out.push_str(&b);
                    out.push(':');
                }
            } else {
                out.push_str(&a);
                out.push_str(&b);
                out.push(':');
            }
        }
        out
    }
}

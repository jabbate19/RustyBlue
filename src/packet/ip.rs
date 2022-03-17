use super::protocol::*;
use super::arp::ARP;

pub struct IP<'a> {
    src: String,
    dst: String,
    protocol: Layer4Protocol,
    arp: Option<ARP>,
    payload: &'a [u8],
}

impl<'a> IP<'a> {
    pub fn new(data: &[u8], protocol: Layer3Protocol) -> Option<IP> {
        match protocol {
            Layer3Protocol::ARP => Some(IP {
                src: format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]),
                dst: format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]),
                protocol: IP::get_protocol(&data[9]),
                arp: ARP::new(&data),
                payload: &data[20..],
            }),
            _ => Some(IP {
                src: format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]),
                dst: format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]),
                protocol: IP::get_protocol(&data[9]),
                arp: None,
                payload: &data[20..],
            }),
        }
    }
    
    fn get_protocol(byte: &u8) -> Layer4Protocol {
        match byte {
            6 => Layer4Protocol::TCP,
            17 => Layer4Protocol::UDP,
            1 => Layer4Protocol::ICMP,
            58 => Layer4Protocol::ICMPv6,
            _ => Layer4Protocol::Unknown,
        }
    }
}
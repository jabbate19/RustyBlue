use super::protocol::*;

pub struct ICMP<'a> {
    src_port: u16,
    dst_port: u16,
    protocol: Layer4Protocol,
    payload: &'a [u8],
}

pub impl<'a> ICMP<'a> {
    pub fn new(data: &[u8], protocol: Layer4Protocol) -> Option<Transport> {
        match protocol {
            Layer4Protocol::ICMP => Transport{
                src_port:
                dst_port:
                protocol:
                payload:
            },
            Layer4Protocol::ICMPv6 => Transport{
                src_port:
                dst_port:
                protocol:
                payload:
            },
            _ => None,
        }
    }
}
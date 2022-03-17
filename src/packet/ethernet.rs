use super::protocol::*;

pub struct Ethernet<'a> {
    pub src: String,
    pub dst: String,
    pub dot1q: bool,
    pub pcp: Option<u8>,
    pub dei: Option<bool>,
    pub vid: Option<u16>,
    pub ethertype: Layer3Protocol,
    pub payload: &'a [u8],
}

impl<'a> Ethernet<'a> {
    pub fn new(data: &[u8]) -> Option<Ethernet> {
        if data.len() >= 18 {
            if data[12] == 129 && data[13] == 0 {
                return Some(Ethernet{
                    src: format!(
                        "{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}",
                        data[6], data[7], data[8], data[9], data[10], data[11]
                    ),
                    dst: format!(
                        "{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}",
                        data[0], data[1], data[2], data[3], data[4], data[5]
                    ),
                    dot1q: true,
                    pcp: Some(0),
                    dei: Some(false),
                    vid: Some(0),
                    ethertype: Ethernet::convert_protocol([data[14], data[15]]),
                    payload: &data[16..],
                });
            }
            return Some(Ethernet{
                src: format!(
                    "{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}",
                    data[6], data[7], data[8], data[9], data[10], data[11]
                ),
                dst: format!(
                    "{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}",
                    data[0], data[1], data[2], data[3], data[4], data[5]
                ),
                dot1q: false,
                pcp: None,
                dei: None,
                vid: None,
                ethertype: Ethernet::convert_protocol([data[12], data[13]]),
                payload: &data[14..],
            });
        }
        None
    }

    fn convert_protocol(protocol: [u8; 2]) -> Layer3Protocol {
        match protocol {
            [8, 0] => Layer3Protocol::IPv4,
            [134, 221] => Layer3Protocol::IPv6,
            [8, 6] => Layer3Protocol::ARP,
            _ => Layer3Protocol::Unknown,
        }
    }
}


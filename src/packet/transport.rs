use super::protocol::*;

pub struct Transport<'a> {
    src_port: u16,
    dst_port: u16,
    protocol: Layer4Protocol,
    payload: &'a [u8],
}

pub impl<'a> Transport<'a> {
    pub fn new(data: &[u8], protocol: Layer4Protocol) -> Option<Transport> {
        match protocol {
            Layer4Protocol::TCP => Transport{
                src_port: ((data[0] as u16) << 8) | data[1] as u16,
                dst_port: ((data[2] as u16) << 8) | data[3] as u16,
                protocol: protocol,
                payload: &data[32..],
            },
            Layer4Protocol::UDP => Transport{
                src_port: ((data[0] as u16) << 8) | data[1] as u16,
                dst_port: ((data[2] as u16) << 8) | data[3] as u16,
                protocol: protocol,
                payload: &data[8..],
            },
            _ => None,
        }
    }
}
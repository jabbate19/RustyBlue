use super::protocol::*;
use byteorder::{ByteOrder, LittleEndian};
use std::{fmt::Display, io, vec::Vec};

pub struct MacAddr([u8; 6]);

impl Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Outsourcing the MAC display logic to here
        write!(
            f,
            "{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5],
        )
    }
}

// Outsource the MAC Address creation logic to here
// Also give it the ability to clone the array bytes from the
// source to clean up some lifetime stuffs
impl From<&[u8]> for MacAddr {
    fn from(data: &[u8]) -> Self {
        let mut mac_bytes = [0u8; 6];
        mac_bytes.clone_from_slice(&data[0..6]);
        Self(mac_bytes)
    }
}

impl From<String> for MacAddr {
    fn from(data: String) -> Self {
        let mut hexes = [0u8; 6];
        hex::decode_to_slice(data.replace(':', ""), &mut hexes).expect("Decoding failed");
        MacAddr(hexes)
    }
}

impl PartialEq for MacAddr {
    fn eq(&self, other: &Self) -> bool {
        println!("{:?} | {:?}", self.0, other.0);
        self.0 == other.0
    }
}

pub struct Dot1Q {
    pcp: u8,
    dei: bool,
    vid: u16,
}

impl From<&[u8]> for Dot1Q {
    fn from(data: &[u8]) -> Self {
        let mut field_bits: u16 = ((data[2] as u16) << 8) | data[3] as u16;
        let vid = field_bits & 0b111111111111;
        field_bits >>= 12;
        let dei = (field_bits & 0b1) == 1;
        field_bits >>= 1;
        let pcp = field_bits & 0b111;
        Self {
            pcp: pcp.try_into().unwrap(),
            dei,
            vid,
        }
    }
}

pub(crate) const ETHER_FRAME_MIN_SIZE: usize = 18;

pub struct Ethernet {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub dot1q: Option<Dot1Q>,
    pub ethertype: Layer3,
    pub payload: Vec<u8>,
}

impl TryFrom<Vec<u8>> for Ethernet {
    type Error = io::Error;

    /// Try to read an Ethernet packet from bytes
    ///
    /// ## Errors
    /// * [`std::io::ErrorKind::UnexpectedEof`] - If input data array too short
    fn try_from(packet_bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if packet_bytes.len() < ETHER_FRAME_MIN_SIZE {
            return Err(Self::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Not enough bytes to construct Ethernet packet",
            ));
        }
        if packet_bytes[12] == 129 && packet_bytes[13] == 0 {
            return Ok(Ethernet {
                dst: MacAddr::from(&packet_bytes[0..6]),
                src: MacAddr::from(&packet_bytes[6..12]),
                dot1q: Some(Dot1Q::from(&packet_bytes[12..15])),
                ethertype: Layer3::from(LittleEndian::read_u16(&[
                    packet_bytes[15],
                    packet_bytes[14],
                ])),
                payload: packet_bytes[16..].to_vec(),
            });
        }
        Ok(Ethernet {
            dst: MacAddr::from(&packet_bytes[0..6]),
            src: MacAddr::from(&packet_bytes[6..12]),
            dot1q: None,
            ethertype: Layer3::from(LittleEndian::read_u16(&[
                packet_bytes[13],
                packet_bytes[12],
            ])),
            payload: packet_bytes[14..].to_vec(),
        })
    }
}

use self::ethernet::Ethernet;

pub(crate) mod arp;
pub(crate) mod ethernet;
pub(crate) mod icmp;
pub(crate) mod ip;
pub(crate) mod protocol;
pub(crate) mod transport;

// Can really take advantage of structured-enums here and through the packet processing logic
pub(crate) enum Packet {
    Ethernet(Ethernet),
    Unknown,
}

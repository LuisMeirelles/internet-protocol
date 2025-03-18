use etherparse::Ipv4HeaderSlice;
use std::io;
use tun_tap::{Iface, Mode};

const IPV4_PROTO: u16 = 0x0800;
const TCP_PROTO: u8 = 0x06;

fn main() -> io::Result<()> {
    let interface = Iface::new("tun0", Mode::Tun)?;

    loop {
        let mut buffer = [0u8; 1504];
        let packet_length = interface.recv(&mut buffer)?;

        let ethernet_protocol = u16::from_be_bytes([buffer[2], buffer[3]]);

        if ethernet_protocol != IPV4_PROTO {
            continue;
        }

        let _ethernet_flags = u16::from_be_bytes([buffer[0], buffer[1]]);
        match Ipv4HeaderSlice::from_slice(&buffer[4..packet_length]) {
            Ok(p) => {
                let protocol = p.protocol();
                let protocol_code: u8 = protocol.into();

                if protocol_code != TCP_PROTO {
                    continue;
                }

                let payload_length = p.payload_len().unwrap();
                let source = p.source_addr();
                let destination = p.destination_addr();
                let protocol_abbreviation = protocol.keyword_str().unwrap();

                println!(
                    "{} → {}; {} bytes of {}",
                    source, destination, payload_length, protocol_abbreviation,
                );
            }
            Err(e) => {
                eprintln!("skipping unknown packet: {:?}", e);
            }
        }
    }
}

mod tcp;

use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use std::{collections::HashMap, io, net::Ipv4Addr};
use tun_tap::{Iface, Mode};

const IPV4_CODE: u16 = 0x0800;
const TCP_PROTO: u8 = 0x06;

#[derive(Hash, PartialEq, Eq, Clone, Copy, Debug)]
struct Quad {
    source: (Ipv4Addr, u16),
    destination: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut connections: HashMap<Quad, tcp::State> = Default::default();
    let interface = Iface::new("tun0", Mode::Tun)?;

    loop {
        let mut buffer = [0u8; 1504];

        let packet_length = interface.recv(&mut buffer)?;

        let _ethernet_flags = u16::from_be_bytes([buffer[0], buffer[1]]);

        let ip_version = u16::from_be_bytes([buffer[2], buffer[3]]);

        if ip_version != IPV4_CODE {
            continue;
        }

        match Ipv4HeaderSlice::from_slice(&buffer[4..packet_length]) {
            Ok(ip_header) => {
                let protocol = ip_header.protocol();
                let protocol_code: u8 = protocol.into();

                if protocol_code != TCP_PROTO {
                    continue;
                }

                match TcpHeaderSlice::from_slice(&buffer[4 + ip_header.slice().len()..]) {
                    Ok(tcp_header) => {
                        let ip_header_size = ip_header.slice().len();
                        let tcp_header_size = tcp_header.slice().len();

                        let data_offset = 4 + ip_header_size + tcp_header_size;

                        let source_address = ip_header.source_addr();
                        let source_port: u16 = tcp_header.source_port();
                        let source = (source_address, source_port);

                        let destination_address = ip_header.destination_addr();
                        let destination_port: u16 = tcp_header.destination_port();
                        let destination = (destination_address, destination_port);

                        connections
                            .entry(Quad {
                                source,
                                destination,
                            })
                            .or_default()
                            .on_packet(ip_header, tcp_header, &buffer[data_offset..]);
                    }
                    Err(e) => {
                        eprintln!("skipping unknown TCP packet: {:?}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("skipping unknown packet: {:?}", e);
            }
        }
    }
}

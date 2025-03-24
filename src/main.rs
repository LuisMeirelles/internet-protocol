mod tcp;

use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use std::{
    collections::{HashMap, hash_map::Entry},
    io,
    net::Ipv4Addr,
};
use tun_tap::{Iface, Mode};

const TCP_PROTO: u8 = 0x06;

#[derive(Hash, PartialEq, Eq, Clone, Copy, Debug)]
struct Quad {
    source: (Ipv4Addr, u16),
    destination: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut connections: HashMap<Quad, tcp::Connection> = Default::default();
    let mut interface = Iface::without_packet_info("tun0", Mode::Tun)?;

    loop {
        let mut buffer = [0u8; 1500];

        let packet_length = interface.recv(&mut buffer)?;

        match Ipv4HeaderSlice::from_slice(&buffer[..packet_length]) {
            Ok(ip_header) => {
                let protocol = ip_header.protocol();
                let protocol_code: u8 = protocol.into();

                if protocol_code != TCP_PROTO {
                    continue;
                }

                match TcpHeaderSlice::from_slice(&buffer[ip_header.slice().len()..packet_length]) {
                    Ok(tcp_header) => {
                        let ip_header_size = ip_header.slice().len();
                        let tcp_header_size = tcp_header.slice().len();

                        let data_offset = ip_header_size + tcp_header_size;

                        let source_address = ip_header.source_addr();
                        let source_port: u16 = tcp_header.source_port();
                        let source = (source_address, source_port);

                        let destination_address = ip_header.destination_addr();
                        let destination_port: u16 = tcp_header.destination_port();
                        let destination = (destination_address, destination_port);

                        match connections.entry(Quad {
                            source,
                            destination,
                        }) {
                            Entry::Occupied(mut connection) => connection.get_mut().on_packet(
                                &mut interface,
                                ip_header,
                                tcp_header,
                                &buffer[data_offset..packet_length],
                            )?,
                            Entry::Vacant(connections) => {
                                if let Some(c) =
                                    tcp::Connection::accept(&mut interface, ip_header, tcp_header)?
                                {
                                    connections.insert(c);
                                }
                            }
                        }
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

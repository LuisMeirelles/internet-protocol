use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};

#[derive(Default)]
pub struct State;

impl State {
    pub fn on_packet(&self, ip_header: Ipv4HeaderSlice, tcp_header: TcpHeaderSlice, data: &[u8]) {
        println!(
            "{}:{} → {}:{} = {} bytes",
            ip_header.source_addr(),
            tcp_header.source_port(),
            ip_header.destination_addr(),
            tcp_header.destination_port(),
            data.len(),
        );
        println!();
        println!("data: {:?}", data);
        println!();
        println!();
    }
}

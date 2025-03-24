use std::io;

use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use tun_tap::Iface;

#[allow(dead_code)]
#[derive(Default)]
pub enum State {
    #[default]
    Listen,
    Closed,
    SynRcvd,
    // SynSent,
    // Estab,
}

#[derive(Default)]
pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
}

#[derive(Default)]
struct SendSequenceSpace {
    una: u32,
    nxt: u32,
    wnd: u16,
    iss: u32,
}

#[derive(Default)]
struct ReceiveSequenceSpace {
    nxt: u32,
    wnd: u16,
    irs: u32,
}

impl Connection {
    pub fn accept(
        interface: &mut Iface,
        ip_header: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
    ) -> io::Result<Option<Connection>> {
        let mut buf = [0u8; 1500];

        if !tcp_header.syn() {
            // SYN packet expected
            return Ok(None);
        }

        let iss = 0;
        let irs = tcp_header.sequence_number();

        let connection = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss + 1,
                wnd: 64240,
            },
            recv: ReceiveSequenceSpace {
                irs,
                nxt: irs + 1,
                wnd: tcp_header.window_size(),
            },
        };

        /*                      TCP header format

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |          Source Port          |       Destination Port        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        Sequence Number                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Acknowledgment Number                      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Data |       |C|E|U|A|P|R|S|F|                               |
        | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
        |       |       |R|E|G|K|H|T|N|N|                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |           Checksum            |         Urgent Pointer        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                           [Options]                           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               :
        :                             Data                              :
        :                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

        let mut tcp_header_reply = TcpHeader::new(
            tcp_header.destination_port(),
            tcp_header.source_port(),
            connection.send.iss,
            connection.send.wnd,
        );

        tcp_header_reply.syn = true;
        tcp_header_reply.ack = true;
        tcp_header_reply.acknowledgment_number = connection.recv.nxt;

        let ip_header_reply = Ipv4Header::new(
            tcp_header_reply.header_len_u16(),
            64,
            IpNumber::TCP,
            ip_header.destination(),
            ip_header.source(),
        )
        .unwrap();

        tcp_header_reply.checksum = tcp_header_reply
            .calc_checksum_ipv4(&ip_header_reply, &[])
            .unwrap();

        let unwritten = {
            let mut unwritten_buf = &mut buf[..];

            ip_header_reply.write(&mut unwritten_buf)?;
            tcp_header_reply.write(&mut unwritten_buf)?;

            unwritten_buf.len()
        };

        let written = buf.len() - unwritten;

        interface.send(&buf[..written])?;

        Ok(Some(connection))
    }

    #[allow(unused_variables)]
    pub fn on_packet(
        &mut self,
        interface: &mut Iface,
        ip_header: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<()> {
        print!("{}", String::from_utf8_lossy(data));
        Ok(())
    }
}

use std::io;
use bytes::BytesMut;
use ethereum_types::Public;
use rlp::{self, RlpStream};
use tokio_codec::{Encoder, Decoder};
use rlpx;
use super::{Packet, UserMessage};
use super::packet::{
	PACKET_HELLO,
	PACKET_DISCONNECT,
	PACKET_PING,
	PACKET_PONG,
	PACKET_GET_PEERS,
	PACKET_PEERS,
	PACKET_USER,
	PACKET_LAST
};

pub struct Codec {
	inner: rlpx::Codec,
}

impl Codec {
	pub fn new(inner: rlpx::Codec) -> Codec {
		Codec {
			inner,
		}
	}
}

impl Encoder for Codec {
	type Item = Packet;
	type Error = io::Error;

	fn encode(&mut self, data: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
		let mut rlp = RlpStream::new();
		rlp.append(&data.id());
		rlp.append_raw(&data.body(), 1);
		let packet = rlpx::Packet {
			// TODO: protocol
			protocol: 0,
			data: rlp.drain().into(),
		};
		self.inner.encode(packet, buf)?;
		Ok(())
	}
}

impl Decoder for Codec {
	type Item = Packet;
	type Error = io::Error;

	fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
		let mut packet = match self.inner.decode(buf)? {
			Some(packet) => packet,
			None => return Ok(None),
		};

		// TODO: validate len properly
		if packet.data.len() < 2 {
			return Err(io::Error::new(io::ErrorKind::Other, "Codec::decode failed"));
		}

		let packet_id = packet.data[0];

		match packet_id {
			PACKET_HELLO => {
				let hello = rlp::decode(&packet.data[1..])
					.map_err(|_| io::Error::new(io::ErrorKind::Other, "Codec::decode failed"))?;
				Ok(Some(Packet::Hello(hello)))
			},
			PACKET_DISCONNECT => {
				unimplemented!();
			},
			PACKET_PING => Ok(Some(Packet::Ping)),
			PACKET_PONG => Ok(Some(Packet::Pong)),
			PACKET_GET_PEERS => Ok(Some(Packet::GetPeers)),
			PACKET_PEERS => Ok(Some(Packet::Peers)),
			PACKET_USER ... PACKET_LAST => {
				let _ = packet.data.split_to(1);
				let data = packet.data.take();
				Ok(Some(Packet::UserMessage(UserMessage {
					id: packet_id,
					data,
				})))
			},
			_ => {
				Err(io::Error::new(io::ErrorKind::Other, format!("Codec::decode failed. Unknwon packet_id: {}", packet_id)))
			},
		}
	}
}

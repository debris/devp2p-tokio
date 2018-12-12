use std::io;
use bytes::BytesMut;
use rlp::{self, RlpStream};
use tokio_codec::{Encoder, Decoder};
use rlpx;
use std::borrow::Cow;

const PACKET_HELLO: u8 = 0x80;
const PACKET_DISCONNECT: u8 = 0x01;
const PACKET_PING: u8 = 0x02;
const PACKET_PONG: u8 = 0x03;
const PACKET_GET_PEERS: u8 = 0x04;
const PACKET_PEERS: u8 = 0x05;
const PACKET_USER: u8 = 0x10;
const PACKET_LAST: u8 = 0x7f;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum DisconnectReason
{
	DisconnectRequested,
	TCPError,
	BadProtocol,
	UselessPeer,
	TooManyPeers,
	DuplicatePeer,
	IncompatibleProtocol,
	NullIdentity,
	ClientQuit,
	UnexpectedIdentity,
	LocalIdentity,
	PingTimeout,
	Unknown,
}

#[derive(Debug, PartialEq)]
pub enum Packet {
	Disconnect(DisconnectReason),
	Ping,
	Pong,
}

impl Packet {
	fn id(&self) -> u32 {
		match *self {
			Packet::Disconnect(_) => PACKET_DISCONNECT as u32,
			Packet::Ping => PACKET_PING as u32,
			Packet::Pong => PACKET_PONG as u32,
		}
	}

	fn body(&self) -> Cow<[u8]> {
		match *self {
			Packet::Ping | Packet::Pong => Cow::Borrowed(&rlp::EMPTY_LIST_RLP),
			Packet::Disconnect(reason) => {
				let mut rlp = RlpStream::new_list(1);
				rlp.append(&(reason as u8));
				Cow::Owned(rlp.drain())
			},
		}
	}
}

pub struct Codec<C> {
	inner: C,
}

impl<C> Codec<C> {
	pub fn new(inner: C) -> Codec<C> {
		Codec {
			inner,
		}
	}
}

impl<C> Encoder for Codec<C> where C: Encoder<Item = rlpx::Packet, Error = io::Error> {
	type Item = Packet;
	type Error = io::Error;

	fn encode(&mut self, data: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
		let mut rlp = RlpStream::new();
		rlp.append(&data.id());
		rlp.append_raw(&data.body(), 1);
		let packet = rlpx::Packet {
			// TODO: protocol
			protocol: 0,
			data: rlp.drain(),
		};
		self.inner.encode(packet, buf)?;
		Ok(())
	}
}

impl<C> Decoder for Codec<C> where C: Decoder<Item = rlpx::Packet, Error = io::Error> {
	type Item = Packet;
	type Error = io::Error;

	fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
		let packet = match self.inner.decode(buf)? {
			Some(packet) => packet,
			None => return Ok(None),
		};

		// TODO: validate len properly
		if packet.data.len() < 2 {
			return Err(io::Error::new(io::ErrorKind::Other, "Codec::decode failed"));
		}

		match packet.data[0] {
			PACKET_PING => Ok(Some(Packet::Ping)),
			PACKET_PONG => Ok(Some(Packet::Pong)),
			_ => {
				unimplemented!();
			},
		}
	}
}

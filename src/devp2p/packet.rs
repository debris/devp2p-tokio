use std::borrow::Cow;
use bytes::BytesMut;
use ethereum_types::Public;
use rlp::{self, RlpStream, Rlp};

pub const PACKET_HELLO: u8 = 0x80;
pub const PACKET_DISCONNECT: u8 = 0x01;
pub const PACKET_PING: u8 = 0x02;
pub const PACKET_PONG: u8 = 0x03;
pub const PACKET_GET_PEERS: u8 = 0x04;
pub const PACKET_PEERS: u8 = 0x05;
pub const PACKET_USER: u8 = 0x10;
pub const PACKET_LAST: u8 = 0x7f;

/// Protocol / handler id
pub type ProtocolId = [u8; 3];

#[derive(Debug, PartialEq, Eq)]
/// Protocol info
pub struct CapabilityInfo {
	/// Protocol ID
	pub protocol: ProtocolId,
	/// Protocol version
	pub version: u8,
}

impl rlp::Decodable for CapabilityInfo {
	fn decode(rlp: &Rlp) -> Result<Self, rlp::DecoderError> {
		let p: Vec<u8> = rlp.val_at(0)?;
		if p.len() != 3 {
			return Err(rlp::DecoderError::Custom("Invalid subprotocol string length. Should be 3"));
		}

		let mut protocol = [0u8; 3];
		protocol.copy_from_slice(&p);

		let info = CapabilityInfo {
			protocol,
			version: rlp.val_at(1)?,
		};

		Ok(info)
	}
}

impl rlp::Encodable for CapabilityInfo {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(2);
		s.append(&&self.protocol[..]);
		s.append(&self.version);
	}
}

#[derive(Debug, PartialEq, RlpEncodable, RlpDecodable)]
pub struct Hello {
	pub protocol_version: u32,
	pub client_version: String,
	pub capabilities: Vec<CapabilityInfo>,
	pub local_endpoint_port: u16,
	pub host_public: Public,
}

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

impl From<u8> for DisconnectReason {
	fn from(n: u8) -> Self {
		match n {
			0 => DisconnectReason::DisconnectRequested,
			1 => DisconnectReason::TCPError,
			2 => DisconnectReason::BadProtocol,
			3 => DisconnectReason::UselessPeer,
			4 => DisconnectReason::TooManyPeers,
			5 => DisconnectReason::DuplicatePeer,
			6 => DisconnectReason::IncompatibleProtocol,
			7 => DisconnectReason::NullIdentity,
			8 => DisconnectReason::ClientQuit,
			9 => DisconnectReason::UnexpectedIdentity,
			10 => DisconnectReason::LocalIdentity,
			11 => DisconnectReason::PingTimeout,
			_ => DisconnectReason::Unknown,
		}
	}
}

impl rlp::Decodable for DisconnectReason {
	fn decode(rlp: &Rlp) -> Result<Self, rlp::DecoderError> {
		let val: u8 = rlp.val_at(0)?;
		Ok(val.into())
	}
}

impl rlp::Encodable for DisconnectReason {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(1);
		s.append(&(*self as u8));
	}
}

#[derive(Debug, PartialEq)]
pub struct UserMessage {
	/// id should be in range `PACKET_USER` and `PACKET_LAST`
	pub id: u8,
	pub data: BytesMut,
}

#[derive(Debug, PartialEq)]
pub enum Packet {
	Hello(Hello),
	Disconnect(DisconnectReason),
	Ping,
	Pong,
	GetPeers,
	Peers,
	UserMessage(UserMessage)
}

impl Packet {
	pub(crate) fn id(&self) -> u8 {
		match *self {
			Packet::Hello(_) => PACKET_HELLO,
			Packet::Disconnect(_) => PACKET_DISCONNECT,
			Packet::Ping => PACKET_PING,
			Packet::Pong => PACKET_PONG,
			Packet::Peers => PACKET_PEERS,
			Packet::GetPeers => PACKET_GET_PEERS,
			Packet::UserMessage(UserMessage { id, .. }) => id,
		}
	}

	pub(crate) fn body(&self) -> Cow<[u8]> {
		match *self {
			Packet::Hello(ref hello) => Cow::Owned(rlp::encode(hello)),
			Packet::Ping | Packet::Pong => Cow::Borrowed(&rlp::EMPTY_LIST_RLP),
			Packet::Disconnect(ref reason) => Cow::Owned(rlp::encode(reason)),
			Packet::Peers | Packet::GetPeers => {
				unimplemented!("sending peers and get_peers is unsupported");
			},
			Packet::UserMessage(UserMessage { ref data, .. }) => Cow::Borrowed(data),
		}
	}
}

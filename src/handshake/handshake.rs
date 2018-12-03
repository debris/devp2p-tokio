use std::io;
use ethereum_types::{Public, H256};
use ethkey::{self, Generator, Secret, KeyPair};
use futures::{Future, Poll};
use futures::future::Either;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::io::{read_exact, ReadExact, write_all, WriteAll};
use super::packet::{RawAckPacket, RawAuthPacket, AuthPacket, AckPacket, AuthPacketEip8, AckPacketEip8};

const PROTOCOL_VERSION: u64 = 4;

/// `Future` used to establish a connection with a remote node.
pub struct Handshake<A> {
	inner: Either<InitHandshake<A>, AcceptHandshake<A>>,
}

impl<A> Handshake<A> where A: AsyncRead + AsyncWrite {
	/// Initiate connection to the remote node.
	pub fn init(io: A, host: KeyPair, nonce: H256, remote_public: &Public) -> io::Result<Self> {
		let ecdhe = ethkey::Random.generate()
			.map_err(|_| io::Error::new(io::ErrorKind::Other, "Handshake::init failed"))?;

		let auth_packet = AuthPacket::new(host.secret(), *host.public(), remote_public, nonce, &ecdhe)?;

		let init = InitHandshake {
			state: InitHandshakeState::WriteAuth(write_all(io, auth_packet.encrypt(remote_public)?)),
			secret: host.secret().clone(),
			ecdhe,
			nonce,
		};

		let handshake = Handshake {
			inner: Either::A(init),
		};
		
		Ok(handshake)
	}

	/// Accept connection from a remote node.
	pub fn accept(io: A, secret: Secret, nonce: H256) -> io::Result<Self> {
		let accept = AcceptHandshake {
			state: AcceptHandshakeState::ReadAuth(read_exact(io, RawAuthPacket::default())),
			secret,
			// TODO: propagate error
			ecdhe: ethkey::Random.generate()
				.map_err(|_| io::Error::new(io::ErrorKind::Other, "Handshake::accept failed"))?,
			nonce,
		};

		let handshake = Handshake {
			inner: Either::B(accept)
		};

		Ok(handshake)
	}
}

impl<A> Future for Handshake<A> where A: AsyncRead + AsyncWrite {
	type Item = HandshakeData;
	type Error = io::Error;

	fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
		self.inner.poll()
	}
}

/// Result of the `Handshake` future.
#[derive(Debug)]
pub struct HandshakeData {
	/// Handshake public key
	pub remote_ephemeral: Public,
	/// Remote connection nonce.
	pub remote_nonce: H256,
	/// Remote `RLPx` protocol version.
	pub remote_version: u64,
}

enum InitHandshakeState<A> {
	/// Write auth packet.
	WriteAuth(WriteAll<A, RawAuthPacket>),
	/// Read ack packet.
	ReadAck(ReadExact<A, RawAckPacket>),
	/// According to eip8 ack packet may have a variadic size,
	/// so the reading in split into 2 parts.
	ReadAckEip8 {
		/// Ack packet head should always be `Some`. It's wrapped `Option`
		/// we can `take()` it after tail is fetched.
		ack_packet_head: Option<RawAckPacket>,
		ack_packet_tail: ReadExact<A, Vec<u8>>,
	}
}

struct InitHandshake<A>  {
	/// State of init handshake.
	state: InitHandshakeState<A>,
	/// Our secret.
	secret: Secret,
	/// Our ecdh keypair.
	ecdhe: KeyPair,
	/// Nonce
	nonce: H256,
}

impl<A> Future for InitHandshake<A> where A: AsyncRead + AsyncWrite {
	type Item = HandshakeData;
	type Error = io::Error;
	
	fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
		loop {
			let next_state = match self.state {
				InitHandshakeState::WriteAuth(ref mut future) => {
					let (io, _) = try_ready!(future.poll());
					InitHandshakeState::ReadAck(read_exact(io, RawAckPacket::default()))
				},
				InitHandshakeState::ReadAck(ref mut future) => {
					let (io, raw_ack_packet) = try_ready!(future.poll());
					match raw_ack_packet.decrypt(&self.secret) {
						Ok(ack_packet) => {
							let result = HandshakeData {
								remote_ephemeral: ack_packet.ephemeral,
								remote_nonce: ack_packet.nonce,
								remote_version: PROTOCOL_VERSION,
							};

							return Ok(result.into())
						},
						Err(_) => {
							let ack_packet_tail_size = raw_ack_packet.decrypt_eip8_ack_packet_tail_size()?;
							InitHandshakeState::ReadAckEip8 { 
								ack_packet_head: Some(raw_ack_packet),
								ack_packet_tail: read_exact(io, vec![0u8; ack_packet_tail_size]),
							}
						},
					}
				},
				InitHandshakeState::ReadAckEip8 { ref mut ack_packet_head, ref mut ack_packet_tail } => {
					let (io, tail) = try_ready!(ack_packet_tail.poll());
					let ack_packet_eip8 = ack_packet_head
						.take()
						.expect("ack_packet_head is always Some; qed")
						.decrypt_eip8(&self.secret, &tail)?;

					let result = HandshakeData {
						remote_ephemeral: ack_packet_eip8.ephemeral,
						remote_nonce: ack_packet_eip8.nonce,
						remote_version: ack_packet_eip8.version,
					};

					return Ok(result.into());
				},
			};

			self.state = next_state;
		}
	}
}

enum AcceptHandshakeState<A> {
	/// Read auth packet.
	ReadAuth(ReadExact<A, RawAuthPacket>),
	/// According to eip8 auth packet may have a variadic size,
	/// so the reading is split into 2 parts.
	ReadAuthEip8 { 
		/// Auth packet head should always be `Some`. It's wrapped `Option`
		/// we can `take()` it after tail is fetched.
		auth_packet_head: Option<RawAuthPacket>,
		auth_packet_tail: ReadExact<A, Vec<u8>>,
	},
	/// Writing response to standard Auth packet.
	WriteAck {
		result: Option<HandshakeData>,
		write_ack: WriteAll<A, RawAckPacket>
	},
	/// Writing response to eip8 Auth packet.
	WriteAckEip8 {
		result: Option<HandshakeData>,
		write_ack: WriteAll<A, Vec<u8>>
	},
}

struct AcceptHandshake<A>  {
	/// State of accept handshake.
	state: AcceptHandshakeState<A>,
	/// Our secret.
	secret: Secret,
	/// Our ecdh keypair.
	ecdhe: KeyPair,
	/// Nonce
	nonce: H256,
}

impl<A> Future for AcceptHandshake<A> where A: AsyncRead + AsyncWrite {
	type Item = HandshakeData;
	type Error = io::Error;
	
	fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
		loop {
			let next_state = match self.state {
				AcceptHandshakeState::ReadAuth(ref mut future) => {
					let (io, raw_auth_packet) = try_ready!(future.poll());
					match raw_auth_packet.decrypt(&self.secret) {
						Ok(auth_packet) => {
							let ack_packet = AckPacket {
								ephemeral: *self.ecdhe.public(), 
								nonce: self.nonce
							};

							let raw_packet = ack_packet.encrypt(&auth_packet.public)?;

							let result = HandshakeData {
								remote_ephemeral: auth_packet.ephemeral(&self.secret)?,
								remote_nonce: auth_packet.nonce,
								remote_version: PROTOCOL_VERSION,
							};

							AcceptHandshakeState::WriteAck { 
								result: Some(result),
								write_ack: write_all(io, raw_packet),
							}
						},
						Err(_) => {
							let auth_packet_tail_size = raw_auth_packet.decrypt_eip8_auth_packet_tail_size()?;
							AcceptHandshakeState::ReadAuthEip8 {
								auth_packet_head: Some(raw_auth_packet),
								auth_packet_tail: read_exact(io, vec![0u8; auth_packet_tail_size]),
							}
						},
					}
				},
				AcceptHandshakeState::ReadAuthEip8 { ref mut auth_packet_head, ref mut auth_packet_tail } => {
					let (io, tail) = try_ready!(auth_packet_tail.poll());
					let auth_packet_eip8 = auth_packet_head
						.take()
						.expect("auth_packet_head is always Some; qed")
						.decrypt_eip8(&self.secret, &tail)?;
					
					let ack_packet_eip8 = AckPacketEip8 {
						ephemeral: *self.ecdhe.public(),
						nonce: self.nonce,
						version: PROTOCOL_VERSION,
					};

					let raw_packet = ack_packet_eip8.encrypt_eip8(&auth_packet_eip8.public)?;

					let result = HandshakeData {
						remote_ephemeral: auth_packet_eip8.ephemeral(&self.secret)?,
						remote_nonce: auth_packet_eip8.nonce,
						remote_version: auth_packet_eip8.version,
					};

					AcceptHandshakeState::WriteAckEip8 {
						result: Some(result),
						write_ack: write_all(io, raw_packet),
					}
				},
				AcceptHandshakeState::WriteAck { ref mut result, ref mut write_ack } => {
					let (_, _message) = try_ready!(write_ack.poll());
					return Ok(result.take().expect("result is always Some; qed").into())
				},
				AcceptHandshakeState::WriteAckEip8 { ref mut result, ref mut write_ack } => {
					let (_, _message) = try_ready!(write_ack.poll());
					return Ok(result.take().expect("result is always Some; qed").into())
				},
			};

			self.state = next_state;
		}
	}
}

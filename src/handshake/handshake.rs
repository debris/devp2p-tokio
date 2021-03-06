use std::io;
use ethereum_types::{Public, H256};
use ethkey::{self, Generator, KeyPair};
use futures::{Future, Poll};
use futures::future::Either;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::io::{read_exact, ReadExact, write_all, WriteAll};
use super::packet::{RawAckPacket, RawAuthPacket, AuthPacket, AckPacket, AckPacketEip8};

const AUTH_PROTOCOL_VERSION: u64 = 4;

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
			host_keypair: host.clone(),
			ecdhe,
			nonce,
		};

		let handshake = Handshake {
			inner: Either::A(init),
		};
		
		Ok(handshake)
	}

	/// Accept connection from a remote node.
	pub fn accept(io: A, host: KeyPair, nonce: H256) -> io::Result<Self> {
		let accept = AcceptHandshake {
			state: AcceptHandshakeState::ReadAuth(read_exact(io, RawAuthPacket::default())),
			host_keypair: host.clone(),
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
	type Item = (A, HandshakeData);
	type Error = io::Error;

	fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
		self.inner.poll()
	}
}

/// Result of the `Handshake` future.
#[derive(Debug)]
pub struct HandshakeData {
	/// True if we initialized the handshake.
	pub originated: bool,
	/// Our keypair.
	pub our_keypair: KeyPair,
	/// Our ecdh keypair.
	pub ecdhe: KeyPair,
	/// Our nonce.
	pub nonce: H256,
	/// Raw auth packet.
	pub auth_cipher: Vec<u8>,
	/// Raw ack packet.
	pub ack_cipher: Vec<u8>,
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
	ReadAck {
		/// Auth packet that has been sent to the remote node.
		auth_packet: Option<Vec<u8>>,
		/// Reading ack packet
		ack_packet: ReadExact<A, RawAckPacket>
	},
	/// According to eip8 ack packet may have a variadic size,
	/// so the reading in split into 2 parts.
	ReadAckEip8 {
		/// Auth packet that has been sent to the remote node.
		auth_packet: Option<Vec<u8>>,
		/// Ack packet head should always be `Some`. It's wrapped `Option`
		/// we can `take()` it after tail is fetched.
		ack_packet_head: Option<RawAckPacket>,
		ack_packet_tail: ReadExact<A, Vec<u8>>,
	}
}

struct InitHandshake<A>  {
	/// State of init handshake.
	state: InitHandshakeState<A>,
	/// Our keypair.
	host_keypair: KeyPair,
	/// Our ecdh keypair.
	ecdhe: KeyPair,
	/// Nonce
	nonce: H256,
}

impl<A> Future for InitHandshake<A> where A: AsyncRead + AsyncWrite {
	type Item = (A, HandshakeData);
	type Error = io::Error;
	
	fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
		loop {
			let next_state = match self.state {
				InitHandshakeState::WriteAuth(ref mut future) => {
					let (io, auth_packet) = try_ready!(future.poll());
					InitHandshakeState::ReadAck {
						auth_packet: Some(auth_packet.as_ref().to_vec()),
						ack_packet: read_exact(io, RawAckPacket::default())
					}
				},
				InitHandshakeState::ReadAck { ref mut auth_packet, ref mut ack_packet } => {
					let (io, raw_ack_packet) = try_ready!(ack_packet.poll());
					match raw_ack_packet.decrypt(self.host_keypair.secret()) {
						Ok(ack_packet) => {
							let result = HandshakeData {
								originated: true,
								our_keypair: self.host_keypair.clone(),
								ecdhe: self.ecdhe.clone(),
								nonce: self.nonce,
								auth_cipher: auth_packet.take().expect("auth_packet is always Some; qed"),
								ack_cipher: raw_ack_packet.as_ref().to_vec(),
								remote_ephemeral: ack_packet.ephemeral,
								remote_nonce: ack_packet.nonce,
								remote_version: AUTH_PROTOCOL_VERSION,
							};

							return Ok((io, result).into())
						},
						Err(_) => {
							let ack_packet_tail_size = raw_ack_packet.decrypt_eip8_ack_packet_tail_size()?;
							InitHandshakeState::ReadAckEip8 { 
								auth_packet: auth_packet.take(),
								ack_packet_head: Some(raw_ack_packet),
								ack_packet_tail: read_exact(io, vec![0u8; ack_packet_tail_size]),
							}
						},
					}
				},
				InitHandshakeState::ReadAckEip8 { ref mut auth_packet, ref mut ack_packet_head, ref mut ack_packet_tail } => {
					let (io, tail) = try_ready!(ack_packet_tail.poll());
					let (ack_packet_eip8, ack_cipher) = ack_packet_head
						.take()
						.expect("ack_packet_head is always Some; qed")
						.decrypt_eip8(self.host_keypair.secret(), &tail)?;

					let result = HandshakeData {
						originated: true,
						our_keypair: self.host_keypair.clone(),
						ecdhe: self.ecdhe.clone(),
						nonce: self.nonce,
						auth_cipher: auth_packet.take().expect("auth_packet is always Some; qed"),
						ack_cipher,
						remote_ephemeral: ack_packet_eip8.ephemeral,
						remote_nonce: ack_packet_eip8.nonce,
						remote_version: ack_packet_eip8.version,
					};

					return Ok((io, result).into());
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
	/// Our keypair.
	host_keypair: KeyPair,
	/// Our ecdh keypair.
	ecdhe: KeyPair,
	/// Nonce
	nonce: H256,
}

impl<A> Future for AcceptHandshake<A> where A: AsyncRead + AsyncWrite {
	type Item = (A, HandshakeData);
	type Error = io::Error;
	
	fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
		loop {
			let next_state = match self.state {
				AcceptHandshakeState::ReadAuth(ref mut future) => {
					let (io, raw_auth_packet) = try_ready!(future.poll());
					match raw_auth_packet.decrypt(self.host_keypair.secret()) {
						Ok(auth_packet) => {
							let ack_packet = AckPacket {
								ephemeral: *self.ecdhe.public(), 
								nonce: self.nonce
							};

							let raw_packet = ack_packet.encrypt(&auth_packet.public)?;

							let result = HandshakeData {
								originated: false,
								our_keypair: self.host_keypair.clone(),
								ecdhe: self.ecdhe.clone(),
								nonce: self.nonce,
								auth_cipher: raw_auth_packet.as_ref().to_vec(),
								ack_cipher: raw_packet.as_ref().to_vec(),
								remote_ephemeral: auth_packet.ephemeral(self.host_keypair.secret())?,
								remote_nonce: auth_packet.nonce,
								remote_version: AUTH_PROTOCOL_VERSION,
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
					let (auth_packet_eip8, auth_cipher) = auth_packet_head
						.take()
						.expect("auth_packet_head is always Some; qed")
						.decrypt_eip8(self.host_keypair.secret(), &tail)?;
					
					let ack_packet_eip8 = AckPacketEip8 {
						ephemeral: *self.ecdhe.public(),
						nonce: self.nonce,
						version: AUTH_PROTOCOL_VERSION,
					};

					let raw_packet = ack_packet_eip8.encrypt_eip8(&auth_packet_eip8.public)?;

					let result = HandshakeData {
						originated: false,
						our_keypair: self.host_keypair.clone(),
						ecdhe: self.ecdhe.clone(),
						nonce: self.nonce,
						auth_cipher,
						ack_cipher: raw_packet.clone(),
						remote_ephemeral: auth_packet_eip8.ephemeral(self.host_keypair.secret())?,
						remote_nonce: auth_packet_eip8.nonce,
						remote_version: auth_packet_eip8.version,
					};

					AcceptHandshakeState::WriteAckEip8 {
						result: Some(result),
						write_ack: write_all(io, raw_packet),
					}
				},
				AcceptHandshakeState::WriteAck { ref mut result, ref mut write_ack } => {
					let (io, _message) = try_ready!(write_ack.poll());
					return Ok((io, result.take().expect("result is always Some; qed")).into())
				},
				AcceptHandshakeState::WriteAckEip8 { ref mut result, ref mut write_ack } => {
					let (io, _message) = try_ready!(write_ack.poll());
					return Ok((io, result.take().expect("result is always Some; qed")).into())
				},
			};

			self.state = next_state;
		}
	}
}

#[cfg(test)]
mod tests {
	use mock::mock_sockets;
	use super::*;

	#[test]
	fn test_handshake_between_two_nodes() {
		let a_host = ethkey::Random.generate().unwrap();
		let a_nonce = 1.into();
		let b_host = ethkey::Random.generate().unwrap();
		let b_nonce = 2.into();
		let (a_socket, b_socket) = mock_sockets();

		let handshake_a = Handshake::init(a_socket, a_host, a_nonce, b_host.public()).unwrap();
		let handshake_b = Handshake::accept(b_socket, b_host, b_nonce).unwrap();

		let (result_b, future_a) = handshake_a.select(handshake_b).wait().ok().unwrap();
		let result_a = future_a.wait().unwrap();

		let result_a = result_a.1;
		let result_b = result_b.1;

		assert_eq!(result_a.originated, true);
		assert_eq!(result_a.nonce, 1.into());
		assert_eq!(result_a.remote_nonce, 2.into());
		assert_eq!(result_a.remote_version, AUTH_PROTOCOL_VERSION);
		assert_eq!(result_a.ecdhe.public(), &result_b.remote_ephemeral);

		assert_eq!(result_b.originated, false);
		assert_eq!(result_b.nonce, 2.into());
		assert_eq!(result_b.remote_nonce, 1.into());
		assert_eq!(result_b.remote_version, AUTH_PROTOCOL_VERSION);
		assert_eq!(result_b.ecdhe.public(), &result_a.remote_ephemeral);
	}
}

use std::io;
use futures::{Future, Poll, Sink, AsyncSink, Async, Stream, stream};
use futures::sink;
use futures::sync::mpsc;
use tokio_codec::Framed;
use tokio_io::{AsyncRead, AsyncWrite};
use ethkey::KeyPair;
use ethereum_types::{Public, H256};
use rlp::{self, RlpStream};
use devp2p;
use rlpx;
use Handshake;

/// Session object created for every connection.
/// 
/// Trait bound is required, because `Buffer<S>` requires `S: Sink`.
pub struct Session<A> {
	sender: mpsc::Sender<devp2p::Packet>,
	receiver: mpsc::Receiver<devp2p::Packet>,
	packet_to_send: Option<devp2p::Packet>,
	interface: Framed<A, devp2p::Codec>,
}

impl<A> Session<A> where A: AsyncRead + AsyncWrite {
	pub fn init(io: A, host: KeyPair, nonce: H256, remote_public: &Public) -> io::Result<SessionStart<A>> {
		let ss = SessionStart {
			state: SessionStartState::Handshake(Handshake::init(io, host, nonce, remote_public)?),
		};
		Ok(ss)
	}

	pub fn accept(io: A, host: KeyPair, nonce: H256) -> io::Result<SessionStart<A>> {
		let ss = SessionStart {
			state: SessionStartState::Handshake(Handshake::accept(io, host, nonce)?),
		};
		Ok(ss)
	}

	pub fn write_handle(&self) -> SessionWrite {
		SessionWrite {
			sender: self.sender.clone(),
		}
	}
}

impl<A> Stream for Session<A> where A: AsyncRead + AsyncWrite {
	type Item = devp2p::UserMessage;
	type Error = io::Error;

	fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
		loop {
			let packet = match self.packet_to_send.take() {
				Some(packet) => packet,
				None => match self.receiver.poll().expect("mpsc::Receiver::poll never returns Err; qed") {
					Async::Ready(Some(item)) => item,
					Async::Ready(None) => return Ok(None.into()),
					Async::NotReady => {
						break;
					},
				}
			};

			if let AsyncSink::NotReady(packet) = self.interface.start_send(packet)? {
				assert!(self.packet_to_send.is_none(), "self.packet_to_send.take() called before; qed");
				self.packet_to_send = Some(packet);
				break;
			}
		}

		// it doesn't matter if it's completed or not
		let _ = self.interface.poll_complete()?;

		let packet = match try_ready!(self.interface.poll()) {
			Some(packet) => packet,
			None => return Ok(Async::NotReady),
		};

		match packet {
			devp2p::Packet::Hello(_) => {
				// hello should never be received here
				Err(io::Error::new(io::ErrorKind::Other, "Session::poll failed. Unexpected 'Hello' packet."))
			},
			devp2p::Packet::Disconnect(_) => {
				unimplemented!();
			},
			devp2p::Packet::Ping => {
				// TODO: send Pong
				unimplemented!();
			},
			devp2p::Packet::Pong => {
				// TODO: update timers
				Ok(Async::NotReady)
			},
			devp2p::Packet::GetPeers | devp2p::Packet::Peers => {
				// we ignore these packets
				Ok(Async::NotReady)
			}
			devp2p::Packet::UserMessage(message) => {
				Ok(Async::Ready(Some(message)))
			}
		}
	}
}

pub struct SessionSend {
	future: sink::Send<mpsc::Sender<devp2p::Packet>>,
}

impl Future for SessionSend {
	type Item = ();
	type Error = io::Error;

	fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
		let _= try_ready!(
			self.future.poll()
				.map_err(|_| io::Error::new(io::ErrorKind::Other, "SessionSend::poll failed"))
		);
		Ok(Async::Ready(()))
	}
}

pub struct SessionWrite {
	sender: mpsc::Sender<devp2p::Packet>,
}

impl SessionWrite {
	pub fn send(self, packet: devp2p::Packet) -> SessionSend {
		SessionSend {
			future: self.sender.send(packet)
		}
	}
	
	pub fn send_ping(self) -> SessionSend {
		self.send(devp2p::Packet::Ping)
	}

	pub fn send_pong(self) -> SessionSend {
		self.send(devp2p::Packet::Pong)
	}

	pub fn send_disconnect(self, reason: devp2p::DisconnectReason) -> SessionSend {
		self.send(devp2p::Packet::Disconnect(reason))
	}
}

enum SessionStartState<A> where Framed<A, devp2p::Codec>: Sink {
	Handshake(Handshake<A>),
	WriteHello(sink::Send<Framed<A, devp2p::Codec>>),
	ReadHello(stream::StreamFuture<Framed<A, devp2p::Codec>>),
}

pub struct SessionStart<A> where Framed<A, devp2p::Codec>: Sink {
	state: SessionStartState<A>,
}

impl<A> Future for SessionStart<A> where A: AsyncRead + AsyncWrite {
	type Item = Session<A>;
	type Error = io::Error;

	fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
		loop {
			let next_state = match self.state {
				SessionStartState::Handshake(ref mut handshake) => {
					let (io, handshake_data) = try_ready!(handshake.poll());
					let host_public = handshake_data.our_keypair.public().clone();
					let rlpx_codec = rlpx::Codec::new(handshake_data)?;
					let devp2p_codec = devp2p::Codec::new(rlpx_codec);
					let interface = Framed::new(io, devp2p_codec);
					let future = interface.send(devp2p::Packet::Hello(devp2p::Hello {
						// TODO:
						protocol_version: 0,
						client_version: "new-devp2p-rust".into(),
						capabilities: vec![],
						local_endpoint_port: 0,
						host_public,
					}));
					SessionStartState::WriteHello(future)
				},
				SessionStartState::WriteHello(ref mut future) => {
					let interface = try_ready!(future.poll());
					SessionStartState::ReadHello(interface.into_future())
				},
				SessionStartState::ReadHello(ref mut future) => {
					let (hello, interface) = try_ready!(future.poll().map_err(|e| e.0));
					// TODO: verify hello
					// TODO: create session	
					
					let (sender, receiver) = mpsc::channel(5);
					let session = Session {
						interface,
						sender,
						receiver,
						packet_to_send: None,
					};
					return Ok(session.into());
				}
			};

			self.state = next_state;
		}
	}
}

#[cfg(test)]
mod tests {
	use mock::mock_sessions;
	use super::*;

	#[test]
	fn test_ping_pong() {
		let (session_a, session_b) = mock_sessions();

		let _ = session_a.write_handle().send_ping().wait().unwrap();
		// we use select, cause both sessions have to be polled to send && receive a message
		let session_future_a = session_a.into_future();
		let session_future_b = session_b.into_future();
		let ((ping, session_b), future_a) = session_future_a.select(session_future_b).wait().ok().unwrap();
		// TODO:
		//assert_eq!(ping, Some(devp2p::Packet::Ping));
	}
}

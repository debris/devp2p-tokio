use std::io;
use futures::{Future, Poll, Sink, AsyncSink, Async, Stream};
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
	interface: Framed<A, devp2p::Codec<rlpx::Codec>>,
}

impl<A> Session<A> where A: AsyncRead + AsyncWrite {
	pub fn init(io: A, host: KeyPair, nonce: H256, remote_public: &Public) -> io::Result<SessionStart<A>> {
		let ss = SessionStart {
			handshake: Handshake::init(io, host, nonce, remote_public)?,
		};
		Ok(ss)
	}

	pub fn accept(io: A, host: KeyPair, nonce: H256) -> io::Result<SessionStart<A>> {
		let ss = SessionStart {
			handshake: Handshake::accept(io, host, nonce)?,
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
	type Item = devp2p::Packet;
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

		self.interface.poll()
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

pub struct SessionStart<A> {
	handshake: Handshake<A>,
}

impl<A> Future for SessionStart<A> where A: AsyncRead + AsyncWrite {
	type Item = Session<A>;
	type Error = io::Error;

	fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
		let (io, handshake_data) = try_ready!(self.handshake.poll());
		let codec = rlpx::Codec::new(handshake_data)?;
		let codec = devp2p::Codec::new(codec);
		let interface = Framed::new(io, codec);
		// TODO: buffer size to constant
		let (sender, receiver) = mpsc::channel(5);
		let session = Session {
			interface,
			sender,
			receiver,
			packet_to_send: None,
		};
		Ok(session.into())
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
		assert_eq!(ping, Some(devp2p::Packet::Ping));
	}
}

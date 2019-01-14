use std::{io, time};
use std::collections::VecDeque;
use futures::{Future, Poll, Sink, AsyncSink, Async, Stream, stream, StartSend};
use futures::sink;
use tokio_codec::Framed;
use tokio_io::{AsyncRead, AsyncWrite};
use ethkey::KeyPair;
use ethereum_types::{Public, H256};
use devp2p;
use rlpx;
use Handshake;
use ping::PingTimeout;

const PING_INTERVAL: time::Duration = time::Duration::from_secs(5);
const PONG_TIMEOUT: time::Duration = time::Duration::from_secs(2);

/// Session object created for every connection.
/// 
/// Trait bound is required, because `Buffer<S>` requires `S: Sink`.
pub struct Session<A> {
	packets_to_send: VecDeque<devp2p::Packet>,
	interface: Framed<A, devp2p::Codec>,
	ping_timeout: PingTimeout,
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
}

impl<A> Sink for Session<A> where A: AsyncRead + AsyncWrite {
	type SinkItem = devp2p::Packet;
	type SinkError = io::Error;

	fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
		self.interface.start_send(item)
	}

	fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
		self.interface.poll_complete()
	}
}

impl<A> Stream for Session<A> where A: AsyncRead + AsyncWrite {
	type Item = devp2p::UserMessage;
	type Error = io::Error;

	fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
		// check if we need to ping
		match self.ping_timeout.poll()? {
			Async::Ready(Some(_)) => {
				self.packets_to_send.push_back(devp2p::Packet::Ping);
			},
			Async::NotReady => {},
			Async::Ready(_) => {
				unreachable!();
			}
		}
	
		// loop running as long as we receive packets and can reply to them
		loop {
			// try to send out all awaiting packets
			loop {
				let packet = match self.packets_to_send.pop_front() {
					Some(packet) => packet,
					None => {
						break;
					}
				};

				// packet couldn't be sent now. let's retry later
				if let AsyncSink::NotReady(packet) = self.interface.start_send(packet)? {
					self.packets_to_send.push_front(packet);
					break;
				}
			}

			// IMPORTANT:
			// no messages will be read until we send out all pending packets
			// to this peer
			let _ = try_ready!(self.interface.poll_complete());

			// get new packet, if available
			let packet = match try_ready!(self.interface.poll()) {
				Some(packet) => packet,
				None => return Ok(Async::NotReady),
			};

			match packet {
				devp2p::Packet::Hello(_) => {
					// hello should never be received here
					return Err(io::Error::new(io::ErrorKind::Other, "Session::poll failed. Unexpected 'Hello' packet."))
				},
				devp2p::Packet::Disconnect(_) => {
					return Ok(Async::Ready(None))
				},
				devp2p::Packet::Ping => {
					self.packets_to_send.push_back(devp2p::Packet::Pong);
				},
				devp2p::Packet::Pong => {
					self.ping_timeout.received_pong()?;
				},
				devp2p::Packet::GetPeers | devp2p::Packet::Peers => {
					// we ignore these packets
				}
				devp2p::Packet::UserMessage(message) => {
					return Ok(Async::Ready(Some(message)))
				}
			}
		}
	}
}

enum SessionStartState<A> where Framed<A, devp2p::Codec>: Sink {
	Handshake(Handshake<A>),
	WriteHello(sink::Send<Framed<A, devp2p::Codec>>),
	ReadHello(stream::StreamFuture<Framed<A, devp2p::Codec>>),
	WritePing(sink::Send<Framed<A, devp2p::Codec>>),
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
					let (packet, interface) = try_ready!(future.poll().map_err(|e| e.0));
					match packet {
						Some(devp2p::Packet::Hello(hello)) => {
							// TODO: verify hello
						},
						None => {
							return Err(io::Error::new(io::ErrorKind::Other, "SessionStart::poll failed. Connection closed"));
						},
						_ => {
							return Err(io::Error::new(io::ErrorKind::Other, "SessionStart::poll failed. Unexpected packet"));
						}
					}

					let future = interface.send(devp2p::Packet::Ping);
					SessionStartState::WritePing(future)
				}
				SessionStartState::WritePing(ref mut future) => {
					let interface = try_ready!(future.poll());
					let session = Session {
						interface,
						packets_to_send: VecDeque::new(),
						ping_timeout: PingTimeout::new_awaiting_for_pong(PING_INTERVAL, PONG_TIMEOUT),
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
	use std::error::Error;
	use mock::mock_sessions;
	use mock_time;
	use super::*;

	#[test]
	fn test_send_user_message() {
		// a sends ping
		// b sends ping
		// a sends user message
		// a reads ping and replies with pong
		// b reads ping and replies with pong
		// b reads user message and returns it
		// a reads pong
		// time is changed
		// a sends ping
		// time is changed
		// a times out

		mock_time::mocked(|timer, _time| {
				let (session_a, session_b) = mock_sessions();

				let user_message = devp2p::UserMessage {
					id: 0x11,
					data: vec![0x1, 0x2, 0x3].into(),
				};

				let session_a = session_a.send(devp2p::Packet::UserMessage(user_message.clone())).wait().unwrap();
				// we use select, cause both sessions have to be polled to send && receive a message
				let session_future_a = session_a.into_future();
				let session_future_b = session_b.into_future();
				let ((message, _session_b), mut future_a) = session_future_a.select(session_future_b).wait().ok().unwrap();
				assert_eq!(message, Some(user_message));
				let _ = future_a.poll();
				mock_time::advance(timer, PING_INTERVAL);
				let _ = future_a.poll();
				mock_time::advance(timer, PONG_TIMEOUT);
				match future_a.wait() {
					Ok(_) => {
						assert!(false, "failed to close the stream");
					},
					Err((err, _session)) => {
						// ok path, pong timeout
						assert_eq!(err.description(), "PingTimeout::poll failed. Pong timeout.");
					}
				}
		});
	}
}

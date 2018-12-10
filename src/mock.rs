use std::io::{self, Read, Write};
use ethkey::Generator;
use futures::sync::mpsc;
use futures::{Sink, Stream, Async, Poll, Future};
use tokio_io::{AsyncRead, AsyncWrite};
use handshake::{HandshakeData, Handshake};

pub struct MockSocket {
	sender: mpsc::Sender<Vec<u8>>,
	receiver: mpsc::Receiver<Vec<u8>>,
	read_buffer: Vec<u8>,
}

impl Read for MockSocket {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		let poll = self.receiver.poll();
		match poll {
			Ok(Async::Ready(Some(bytes))) => {
				self.read_buffer.extend(bytes);
			},
			Ok(Async::NotReady) => return Err(io::ErrorKind::WouldBlock.into()),
			Ok(Async::Ready(None)) => (),
			Err(_) => (),
		}

		let len = (&self.read_buffer as &[u8]).read(buf)?;
		self.read_buffer.split_off(len);
		Ok(len)
	}
}

impl AsyncRead for MockSocket {}

impl Write for MockSocket {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		self.sender.try_send(buf.to_vec()).unwrap();
		Ok(buf.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		self.sender.poll_complete().unwrap();
		Ok(())
	}
}

impl AsyncWrite for MockSocket {
	fn shutdown(&mut self) -> Poll<(), io::Error> {
		self.receiver.close();
		self.sender.close().unwrap();
		Ok(().into())
	}
}

pub fn mock_sockets() -> (MockSocket, MockSocket) {
	let (sender_a, receiver_a) = mpsc::channel(5);
	let (sender_b, receiver_b) = mpsc::channel(5);
	(MockSocket {
		sender: sender_a,
		receiver: receiver_b,
		read_buffer: Vec::default(),
	},
	MockSocket {
		sender: sender_b,
		receiver: receiver_a,
		read_buffer: Vec::default(),
	})
}

pub fn mock_handshake_data() -> (HandshakeData, HandshakeData) {
	let a_host = ethkey::Random.generate().unwrap();
	let a_nonce = 1.into();
	let b_host = ethkey::Random.generate().unwrap();
	let b_nonce = 2.into();
	let (a_socket, b_socket) = mock_sockets();

	let handshake_a = Handshake::init(a_socket, a_host, a_nonce, b_host.public()).unwrap();
	let handshake_b = Handshake::accept(b_socket, b_host, b_nonce).unwrap();

	let (result_b, future_a) = handshake_a.select(handshake_b).wait().ok().unwrap();
	let result_a = future_a.wait().unwrap();

	(result_a, result_b)
}

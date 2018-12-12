use std::io;
use futures::{Stream, Poll};

pub fn start() -> io::Result<(Host, Messages)> {
	unimplemented!();
}

pub struct Host {
}

pub struct ReplyInterface {
}

pub struct Message;

pub struct Messages {
}

impl Stream for Messages {
	type Item = (ReplyInterface, Message);
	type Error = io::Error;

	fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
		unimplemented!();
	}
}


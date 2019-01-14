use std::{io, time};
use futures::{Stream, Future, Poll, Async};
use tokio_timer::Delay;
use tokio_timer::clock::Clock;

enum PingTimeoutStatus {
	Idle,
	WaitingForPong,
}

/// This stream notifies consumer when new `Ping` packets should be sent.
/// It expires if elapsed time since last ping is bigger than `pong_timeout`.
/// To reset `pong_timeout` call `PingTimeout::received_pong`.
pub struct PingTimeout {
	status: PingTimeoutStatus,
	clock: Clock,
	delay: Delay,
	ping_interval: time::Duration,
	pong_timeout: time::Duration,
		
}

impl Stream for PingTimeout {
	type Item = ();
	type Error = io::Error;

	fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
		let poll_result = self.delay.poll().map_err(|_| io::Error::new(io::ErrorKind::Other, "PingTimeout::poll failed."));
		let _ready = try_ready!(poll_result);
		match self.status {
			PingTimeoutStatus::Idle => {
				self.status = PingTimeoutStatus::WaitingForPong;
				self.delay.reset(self.clock.now() + self.pong_timeout);
				// reregister the timeout
				let _ = self.delay.poll()
					.map_err(|_| io::Error::new(io::ErrorKind::Other, "PingTimeout::poll failed. Delay reregister failed."))?;
				Ok(Async::Ready(Some(())))
			},
			PingTimeoutStatus::WaitingForPong => {
				Err(io::Error::new(io::ErrorKind::Other, "PingTimeout::poll failed. Pong timeout."))
			},
		}
	}
}

impl PingTimeout {
	/// Creates new `PingTimeout` instance that is awaiting for `Pong` packets.
	pub fn new_awaiting_for_pong(ping_interval: time::Duration, pong_timeout: time::Duration) -> PingTimeout {
		let clock = Clock::new();
		let delay = Delay::new(clock.now() + pong_timeout);
		PingTimeout {
			status: PingTimeoutStatus::WaitingForPong,
			clock,
			delay,
			ping_interval,
			pong_timeout,
		}
	}

	/// Should be used to notify `PingTimeout` about received `Pong` packet.
	/// Returns an error if we receive 2 consecutive `Pong` packets.
	pub fn received_pong(&mut self) -> io::Result<()> {
		if let PingTimeoutStatus::Idle = self.status {
			return Err(io::Error::new(io::ErrorKind::Other, "PingTimeout::received_pong failed."));
		}

		self.status = PingTimeoutStatus::Idle;
		self.delay.reset(self.clock.now() + self.ping_interval);
		// reregister the timeout
		let _ = self.delay.poll()
			.map_err(|_| io::Error::new(io::ErrorKind::Other, "PingTimeout::received_pong failed. Delay reregister failed."))?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use std::error::Error;
	use mock_time;
	use super::*;

	#[test]
	fn test_ping_timeout() {
		mock_time::mocked(|timer, _time| {
			let ping_interval = time::Duration::from_secs(5);
			let pong_timeout = time::Duration::from_secs(2);
			let mut pt = PingTimeout::new_awaiting_for_pong(ping_interval, pong_timeout);
			assert_not_ready!(pt);
			mock_time::advance(timer, time::Duration::from_secs(1));
			assert_not_ready!(pt);
			pt.received_pong().unwrap();
			mock_time::advance(timer, time::Duration::from_secs(10));
			assert_ready!(pt);
			assert_not_ready!(pt);
			mock_time::advance(timer, time::Duration::from_secs(2));
			assert_eq!(pt.poll().unwrap_err().description(), "PingTimeout::poll failed. Pong timeout.");
		});
	}

}

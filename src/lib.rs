extern crate bytes;
extern crate ethereum_types;
extern crate ethkey;
#[macro_use]
extern crate futures;
extern crate keccak_hash;
extern crate rustc_hex;
extern crate rand;
extern crate crypto as rcrypto;
extern crate rlp;
#[macro_use]
extern crate rlp_derive;
extern crate tiny_keccak;
extern crate tokio_codec;
extern crate tokio_executor;
extern crate tokio_io;
extern crate tokio_tcp;
extern crate tokio_timer;
#[macro_use]
extern crate log;
extern crate parking_lot;

#[cfg(test)]
#[macro_use]
mod mock_time;

mod devp2p;
mod handshake;
mod host;
mod ping;
mod rlpx;
mod session;

#[cfg(test)]
mod mock;

pub use self::handshake::{Handshake, HandshakeData};
pub use self::rlpx::{Codec, Packet};
pub use self::session::Session;

/// Crate protocol version. Different to handshake protocol version.
const PROTOCOL_VERSION: u64 = 5;

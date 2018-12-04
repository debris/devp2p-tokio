use std::io;
use ethereum_types::{H256, H512, H520, Public};
use ethkey::{self, Secret, KeyPair, Signature, recover};
use ethkey::crypto::{ecdh, ecies};
use keccak_hash::keccak;
use rand::random;
use rlp::{Rlp, RlpStream};

const V4_AUTH_PACKET_SIZE: usize = 307;
const V4_ACK_PACKET_SIZE: usize = 210;
// Amount of bytes added when encrypting with encryptECIES.
const ECIES_OVERHEAD: usize = 113;

/// Helpers structure used for reading auth packet.
pub(crate) struct RawAuthPacket([u8; V4_AUTH_PACKET_SIZE]);

impl Default for RawAuthPacket {
	fn default() -> Self {
		RawAuthPacket([0u8; V4_AUTH_PACKET_SIZE])
	}
}

impl AsRef<[u8]> for RawAuthPacket {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl AsMut<[u8]> for RawAuthPacket {
	fn as_mut(&mut self) -> &mut [u8] {
		&mut self.0
	}
}

impl RawAuthPacket {
	pub fn decrypt(&self, secret: &Secret) -> io::Result<AuthPacket> {
		let data = ecies::decrypt(secret, &[], &self.0)
			.map_err(|_| io::Error::new(io::ErrorKind::Other, "RawAuthPacket::decrypt failed"))?;
		let mut signature = H520::default();
		let mut ecdh_public_hash = H256::default();
		let mut public = H512::default();
		let mut nonce = H256::default();
		signature.copy_from_slice(&data[0..65]);
		ecdh_public_hash.copy_from_slice(&data[65..97]);
		public.copy_from_slice(&data[97..161]);
		nonce.copy_from_slice(&data[161..193]);

		let packet = AuthPacket {
			signature: signature.into(),
			ecdh_public_hash,
			public: public.into(),
			nonce,
		};

		Ok(packet)
	}

	pub fn decrypt_eip8_auth_packet_tail_size(&self) -> io::Result<usize> {
		let total = ((u16::from(self.0[0]) << 8 | (u16::from(self.0[1]))) as usize) + 2;
		if total < V4_AUTH_PACKET_SIZE {
			return Err(io::Error::new(io::ErrorKind::Other, "RawAuthPacket::decrypt_eip8_auth_packet_tail_size failed"));
		}
		Ok(total - self.0.len())
	}

	pub fn decrypt_eip8(&self, secret: &Secret, tail: &[u8]) -> io::Result<(AuthPacketEip8, Vec<u8>)> {
		let mut data = vec![0u8; V4_AUTH_PACKET_SIZE + tail.len()];
		data[0..V4_AUTH_PACKET_SIZE].copy_from_slice(&self.0);
		data[V4_AUTH_PACKET_SIZE..].copy_from_slice(tail);
		let auth = ecies::decrypt(secret, &self.0[0..2], &data[2..])
			.map_err(|_| io::Error::new(io::ErrorKind::Other, "RawAuthPacket::decrypt_eip8 failed"))?;
		let err = |_| io::Error::new(io::ErrorKind::Other, "RawAuthPacket::decrypt_eip8 failed");
		let rlp = Rlp::new(&auth);
		let signature: H520 = rlp.val_at(0).map_err(err)?;
		let public: Public = rlp.val_at(1).map_err(err)?;
		let nonce: H256 = rlp.val_at(2).map_err(err)?;
		let version: u64 = rlp.val_at(3).map_err(err)?;
		
		let packet = AuthPacketEip8 {
			signature: signature.into(),
			public,
			nonce,
			version
		};

		Ok((packet, data))
	}
}

#[derive(Debug)]
pub(crate) struct AuthPacket {
	pub signature: Signature,
	pub ecdh_public_hash: H256,
	pub public: Public,
	pub nonce: H256,
}

#[derive(Debug)]
pub(crate) struct AuthPacketEip8 {
	pub signature: Signature,
	pub public: Public,
	pub nonce: H256,
	pub version: u64,
}

impl AuthPacket {
	pub fn new(secret: &Secret, public: Public, remote_public: &Public, nonce: H256, ecdhe: &KeyPair) -> io::Result<Self> {
		// E(remote-pubk, S(ecdhe-random, ecdh-shared-secret^nonce) || H(ecdhe-random-pubk) || pubk || nonce || 0x0)
		let ecdh_shared_secret = ecdh::agree(secret, remote_public)
			.map_err(|_| io::Error::new(io::ErrorKind::Other, "AuthPacket::new failed"))?;
		let signature = ethkey::sign(ecdhe.secret(), &(*ecdh_shared_secret ^ nonce))
			.map_err(|_| io::Error::new(io::ErrorKind::Other, "AuthPacket::new failed"))?;
		let ecdh_public_hash = keccak(ecdhe.public());

		let packet = AuthPacket {
			signature,
			ecdh_public_hash,
			public,
			nonce,
		};

		Ok(packet)
	}

	pub fn encrypt(&self, remote_public: &Public) -> io::Result<RawAuthPacket> {
		let mut data = [0u8; V4_AUTH_PACKET_SIZE - ECIES_OVERHEAD];
		data[0..65].copy_from_slice(&*self.signature);
		data[65..97].copy_from_slice(&self.ecdh_public_hash);
		data[97..161].copy_from_slice(&self.public);
		data[161..193].copy_from_slice(&self.nonce);
		// last byte is 0
		let message = ecies::encrypt(remote_public, &[], &data)
			.map_err(|_| io::Error::new(io::ErrorKind::Other, "AuthPacket::encrypt failed"))?;
		assert_eq!(message.len(), V4_AUTH_PACKET_SIZE);

		let mut result = RawAuthPacket::default();
		result.as_mut().copy_from_slice(&message);
		Ok(result)
	}

	/// Used to retrive remote ephemeral
	pub fn ephemeral(&self, secret: &Secret) -> io::Result<Public> {
		let shared = *ecdh::agree(secret, &self.public)
			.map_err(|_| io::Error::new(io::ErrorKind::Other, "AuthPacket::ephemeral failed"))?;
		recover(&self.signature, &(shared ^ self.nonce))
			.map_err(|_| io::Error::new(io::ErrorKind::Other, "AuthPacket::ephemeral failed"))
	}
}

impl AuthPacketEip8 {
	pub fn ephemeral(&self, secret: &Secret) -> io::Result<Public> {
		let shared = *ecdh::agree(secret, &self.public)
			.map_err(|_| io::Error::new(io::ErrorKind::Other, "AuthPacketEip8::ephemeral failed"))?;
		recover(&self.signature, &(shared ^ self.nonce))
			.map_err(|_| io::Error::new(io::ErrorKind::Other, "AuthPacketEip8::ephemeral failed"))
	}
}

/// Helpers structure used for reading ack packet.
pub(crate) struct RawAckPacket([u8; V4_ACK_PACKET_SIZE]);

impl Default for RawAckPacket {
	fn default() -> Self {
		RawAckPacket([0u8; V4_ACK_PACKET_SIZE])
	}
}

impl AsRef<[u8]> for RawAckPacket {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl AsMut<[u8]> for RawAckPacket {
	fn as_mut(&mut self) -> &mut [u8] {
		&mut self.0
	}
}

impl RawAckPacket {
	pub fn decrypt(&self, secret: &Secret) -> io::Result<AckPacket> {
		let data = ecies::decrypt(secret, &[], &self.0)
			.map_err(|_| io::Error::new(io::ErrorKind::Other, "RawAckPacket::decrypt failed"))?;

		let mut ephemeral = H512::default();
		let mut nonce = H256::default();
		ephemeral.copy_from_slice(&data[0..64]);
		nonce.copy_from_slice(&data[64..96]);

		let ack_packet = AckPacket {
			ephemeral: ephemeral.into(),
			nonce,
		};

		Ok(ack_packet)
	}

	pub fn decrypt_eip8_ack_packet_tail_size(&self) -> io::Result<usize> {
		let total = ((u16::from(self.0[0]) << 8 | (u16::from(self.0[1]))) as usize) + 2;
		if total < V4_ACK_PACKET_SIZE {
			return Err(io::Error::new(io::ErrorKind::Other, "RawAckPacket::decrypt_eip8_ack_packet_tail_size failed"));
		}
		Ok(total - self.0.len())
	}

	pub fn decrypt_eip8(&self, secret: &Secret, tail: &[u8]) -> io::Result<(AckPacketEip8, Vec<u8>)> {
		let mut data = vec![0u8; V4_ACK_PACKET_SIZE + tail.len()];
		data[0..V4_ACK_PACKET_SIZE].copy_from_slice(&self.0);
		data[V4_ACK_PACKET_SIZE..].copy_from_slice(tail);
		let ack = ecies::decrypt(secret, &self.0[0..2], &data[2..])
			.map_err(|_| io::Error::new(io::ErrorKind::Other, "RawAckPacket::decrypt_eip8 failed"))?;
		let err = |_| io::Error::new(io::ErrorKind::Other, "RawAckPacket::decrypt_eip8 failed");
		let rlp = Rlp::new(&ack);
		let ephemeral: Public = rlp.val_at(0).map_err(err)?;
		let nonce: H256 = rlp.val_at(1).map_err(err)?;
		let version: u64 = rlp.val_at(2).map_err(err)?;

		let ack_packet = AckPacketEip8 {
			ephemeral,
			nonce,
			version
		};

		Ok((ack_packet, data))
	}
}

#[derive(Debug)]
pub(crate) struct AckPacket {
	pub ephemeral: Public,
	pub nonce: H256,
}

#[derive(Debug)]
pub(crate) struct AckPacketEip8 {
	pub ephemeral: Public,
	pub nonce: H256,
	pub version: u64,
}

impl AckPacket {
	pub fn encrypt(&self, remote_public: &Public) -> io::Result<RawAckPacket> {
		let mut data = [0u8; V4_ACK_PACKET_SIZE - ECIES_OVERHEAD];
		data[0..64].copy_from_slice(&self.ephemeral);
		data[64..96].copy_from_slice(&self.nonce);
		// last bytes is 0
		let message = ecies::encrypt(remote_public, &[], &data)
			.map_err(|_| io::Error::new(io::ErrorKind::Other, "AckPacket::encrypt failed"))?;
		assert_eq!(message.len(), V4_ACK_PACKET_SIZE);

		let mut result = RawAckPacket::default();
		result.as_mut().copy_from_slice(&message);
		Ok(result)
	}
}

impl AckPacketEip8 {
	pub fn encrypt_eip8(&self, remote_public: &Public) -> io::Result<Vec<u8>> {
		let mut rlp_stream = RlpStream::new_list(3);
		rlp_stream.append(&self.ephemeral);
		rlp_stream.append(&self.nonce);
		rlp_stream.append(&self.version);

		let pad_array = [0u8; 200];
		let pad = &pad_array[0 .. 100 + random::<usize>() % 100];
		rlp_stream.append_raw(pad, 0);

		let encoded = rlp_stream.drain();
		let len = (encoded.len() + ECIES_OVERHEAD) as u16;
		let prefix = [ (len >> 8) as u8, (len & 0xff) as u8 ];
		let message = ecies::encrypt(remote_public, &prefix, &encoded)
			.map_err(|_| io::Error::new(io::ErrorKind::Other, "AckPacketEip8::encrypt failed"))?;

		let mut result = Vec::with_capacity(prefix.len() + message.len());
		result.extend_from_slice(&prefix);
		result.extend(message);

		Ok(result)
	}
}

#[cfg(test)]
mod tests {
	use rustc_hex::FromHex;
	use super::*;

	#[test]
	fn test_read_auth() {
		let secret = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291".parse().unwrap();

		let auth =
			"\
			048ca79ad18e4b0659fab4853fe5bc58eb83992980f4c9cc147d2aa31532efd29a3d3dc6a3d89eaf\
			913150cfc777ce0ce4af2758bf4810235f6e6ceccfee1acc6b22c005e9e3a49d6448610a58e98744\
			ba3ac0399e82692d67c1f58849050b3024e21a52c9d3b01d871ff5f210817912773e610443a9ef14\
			2e91cdba0bd77b5fdf0769b05671fc35f83d83e4d3b0b000c6b2a1b1bba89e0fc51bf4e460df3105\
			c444f14be226458940d6061c296350937ffd5e3acaceeaaefd3c6f74be8e23e0f45163cc7ebd7622\
			0f0128410fd05250273156d548a414444ae2f7dea4dfca2d43c057adb701a715bf59f6fb66b2d1d2\
			0f2c703f851cbf5ac47396d9ca65b6260bd141ac4d53e2de585a73d1750780db4c9ee4cd4d225173\
			a4592ee77e2bd94d0be3691f3b406f9bba9b591fc63facc016bfa8\
			".from_hex().unwrap();

		let mut raw_packet = RawAuthPacket::default();
		raw_packet.as_mut().copy_from_slice(&auth);

		let packet = raw_packet.decrypt(&secret).unwrap();
		assert_eq!("299ca6acfd35e3d72d8ba3d1e2b60b5561d5af5218eb5bc182045769eb422691".from_hex().unwrap(), packet.signature.r());
		assert_eq!("0a301acae3b369fffc4a4899d6b02531e89fd4fe36a2cf0d93607ba470b50f78".from_hex().unwrap(), packet.signature.s());
		assert_eq!(0, packet.signature.v());
		assert_eq!(packet.ecdh_public_hash, "3eb781e508ac1fff27c06cd192e2fe526f85f8f0e266ea55064ba8aefb868fd9".into());
		assert_eq!(packet.public, "fda1cff674c90c9a197539fe3dfb53086ace64f83ed7c6eabec741f7f381cc803e52ab2cd55d5569bce4347107a310dfd5f88a010cd2ffd1005ca406f1842877".into());
		assert_eq!(packet.nonce, "7e968bba13b6c50e2c4cd7f241cc0d64d1ac25c7f5952df231ac6a2bda8ee5d6".into());
	}

	#[test]
	fn test_read_auth_eip8() {
		let secret = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291".parse().unwrap();

		let auth =
			"\
			01b304ab7578555167be8154d5cc456f567d5ba302662433674222360f08d5f1534499d3678b513b\
			0fca474f3a514b18e75683032eb63fccb16c156dc6eb2c0b1593f0d84ac74f6e475f1b8d56116b84\
			9634a8c458705bf83a626ea0384d4d7341aae591fae42ce6bd5c850bfe0b999a694a49bbbaf3ef6c\
			da61110601d3b4c02ab6c30437257a6e0117792631a4b47c1d52fc0f8f89caadeb7d02770bf999cc\
			147d2df3b62e1ffb2c9d8c125a3984865356266bca11ce7d3a688663a51d82defaa8aad69da39ab6\
			d5470e81ec5f2a7a47fb865ff7cca21516f9299a07b1bc63ba56c7a1a892112841ca44b6e0034dee\
			70c9adabc15d76a54f443593fafdc3b27af8059703f88928e199cb122362a4b35f62386da7caad09\
			c001edaeb5f8a06d2b26fb6cb93c52a9fca51853b68193916982358fe1e5369e249875bb8d0d0ec3\
			6f917bc5e1eafd5896d46bd61ff23f1a863a8a8dcd54c7b109b771c8e61ec9c8908c733c0263440e\
			2aa067241aaa433f0bb053c7b31a838504b148f570c0ad62837129e547678c5190341e4f1693956c\
			3bf7678318e2d5b5340c9e488eefea198576344afbdf66db5f51204a6961a63ce072c8926c\
			".from_hex().unwrap();

		let mut raw_packet = RawAuthPacket::default();
		raw_packet.as_mut().copy_from_slice(&auth[..V4_AUTH_PACKET_SIZE]);

		let err = raw_packet.decrypt(&secret).unwrap_err();
		assert_eq!(io::ErrorKind::Other, err.kind());
		assert_eq!("RawAuthPacket::decrypt failed", err.to_string());

		assert_eq!(auth.len() - V4_AUTH_PACKET_SIZE, raw_packet.decrypt_eip8_auth_packet_tail_size().unwrap());

		let packet = raw_packet.decrypt_eip8(&secret, &auth[V4_AUTH_PACKET_SIZE..]).unwrap();
		assert_eq!("299ca6acfd35e3d72d8ba3d1e2b60b5561d5af5218eb5bc182045769eb422691".from_hex().unwrap(), packet.signature.r());
		assert_eq!("0a301acae3b369fffc4a4899d6b02531e89fd4fe36a2cf0d93607ba470b50f78".from_hex().unwrap(), packet.signature.s());
		assert_eq!(0, packet.signature.v());
		assert_eq!(packet.public, "fda1cff674c90c9a197539fe3dfb53086ace64f83ed7c6eabec741f7f381cc803e52ab2cd55d5569bce4347107a310dfd5f88a010cd2ffd1005ca406f1842877".into());
		assert_eq!(packet.nonce, "7e968bba13b6c50e2c4cd7f241cc0d64d1ac25c7f5952df231ac6a2bda8ee5d6".into());
		assert_eq!(packet.version, 4);
	}
}

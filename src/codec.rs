use std::io;
use bytes::BytesMut;
use ethkey::crypto::ecdh;
use ethereum_types::{H128, H256, H512};
use keccak_hash::keccak;
use rcrypto::aessafe::AesSafe256Encryptor;
use rcrypto::blockmodes::{CtrMode, NoPadding, EcbEncryptor, EncPadding};
use rcrypto::buffer::{RefReadBuffer, RefWriteBuffer};
use rcrypto::symmetriccipher::{Encryptor, Decryptor};
use rlp::{Rlp, RlpStream};
use tiny_keccak::Keccak;
use tokio_codec::{Encoder, Decoder};
use handshake::HandshakeData;

const ENCRYPTED_HEADER_LEN: usize = 32;
const MAX_PAYLOAD_SIZE: usize = (1 << 24) - 1;

/// `RLPx` packet.
pub struct Packet {
	pub protocol: u16,
	pub data: Vec<u8>,
}

#[derive(Clone, Copy)]
struct PayloadInfo {
	protocol_id: u16,
	len: usize,
	full_len: usize,
}

enum DecodeState {
	Header,
	Payload(PayloadInfo),
}

fn update_mac(mac: &mut Keccak, mac_encoder: &mut EcbEncryptor<AesSafe256Encryptor, EncPadding<NoPadding>>, seed: H128) {
	let mut prev = H128::default();
	mac.clone().finalize(&mut prev);
	let mut enc = H128::default();
	mac_encoder.encrypt(&mut RefReadBuffer::new(&prev), &mut RefWriteBuffer::new(&mut enc), true)
		.expect("buffers have the right size");
	mac_encoder.reset();
	enc = enc ^ seed;
	mac.update(&enc);
}

fn update_mac_with_empty_seed(mac: &mut Keccak, mac_encoder: &mut EcbEncryptor<AesSafe256Encryptor, EncPadding<NoPadding>>) {
	let mut prev = H128::default();
	mac.clone().finalize(&mut prev);
	let mut enc = H128::default();
	mac_encoder.encrypt(&mut RefReadBuffer::new(&prev), &mut RefWriteBuffer::new(&mut enc), true)
		.expect("buffers have the right size");
	mac_encoder.reset();
	enc = enc ^ prev;
	mac.update(&enc);
}

pub struct Codec {
	/// Decoder state.
	decode_state: DecodeState,
	/// Egress data encryptor.
	encoder: CtrMode<AesSafe256Encryptor>,
	/// Ingress data decryptor.
	decoder: CtrMode<AesSafe256Encryptor>,
	/// Ingress data decryptor.
	mac_encoder: EcbEncryptor<AesSafe256Encryptor, EncPadding<NoPadding>>,
	/// Egress mac.
	egress_mac: Keccak,
	/// Ingress mac.
	ingress_mac: Keccak,
}

impl Codec {
	pub fn new(data: HandshakeData) -> io::Result<Self> {
		let shared = ecdh::agree(data.ecdhe.secret(), &data.remote_ephemeral)
			.map_err(|_| io::Error::new(io::ErrorKind::Other, "Codec::new failed"))?;

		let mut nonce_material = H512::default();
		if data.originated {
			nonce_material[0..32].copy_from_slice(&data.remote_nonce);
			nonce_material[32..64].copy_from_slice(&data.nonce);
		} else {
			nonce_material[0..32].copy_from_slice(&data.nonce);
			nonce_material[32..64].copy_from_slice(&data.remote_nonce);
		}

		let mut key_material = H512::default();
		key_material[0..32].copy_from_slice(&shared);
		key_material[32..64].copy_from_slice(&keccak(&nonce_material));
		let key_material_hash = keccak(&key_material);
		key_material[32..64].copy_from_slice(&key_material_hash);
		let key_material_hash = keccak(&key_material);
		key_material[32..64].copy_from_slice(&key_material_hash);

		let iv = vec![0u8; 16];
		let encoder = CtrMode::new(AesSafe256Encryptor::new(&key_material[32..64]), iv);
		let iv = vec![0u8; 16];
		let decoder = CtrMode::new(AesSafe256Encryptor::new(&key_material[32..64]), iv);

		let key_material_hash = keccak(&key_material);
		key_material[32..64].copy_from_slice(&key_material_hash);

		let mac_encoder = EcbEncryptor::new(AesSafe256Encryptor::new(&key_material[32..64]), NoPadding);

		let mut mac_material = H256::default();
		mac_material.copy_from_slice(&key_material[32..64]);
		mac_material = mac_material ^ data.remote_nonce;

		let mut egress_mac = Keccak::new_keccak256();
		egress_mac.update(&mac_material);
		if data.originated {
			egress_mac.update(&data.auth_cipher);
		} else {
			egress_mac.update(&data.ack_cipher);
		}

		let mut mac_material = H256::default();
		mac_material.copy_from_slice(&key_material[32..64]);
		mac_material = mac_material ^ data.nonce;

		let mut ingress_mac = Keccak::new_keccak256();
		ingress_mac.update(&mac_material);
		if data.originated {
			ingress_mac.update(&data.ack_cipher);
		} else {
			ingress_mac.update(&data.auth_cipher);
		}

		let codec = Codec {
			decode_state: DecodeState::Header,
			encoder,
			decoder,
			mac_encoder, 
			egress_mac,
			ingress_mac,
		};

		Ok(codec)
	}
}

impl Encoder for Codec {
	type Item = Packet;
	type Error = io::Error;

	fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
		let len = item.data.len();
		if len > MAX_PAYLOAD_SIZE {
			return Err(io::Error::new(io::ErrorKind::Other, "Encoder::encode failed"));
		}

		let mut header = RlpStream::new();
		// first we append payload_len
		header.append_raw(&[(len >> 16) as u8, (len >> 8) as u8, len as u8], 1);
		// then we append a list of two items
		// the first one is protocol_id set to 0 (mk, not sure why)
		// the second one is set to zero (mk, not sure what it is at all)
		header.append_raw(&[0xc2u8, 0x80u8, 0x80u8], 1);

		let mut header = header.out();
		let padding = (16 - (len % 16)) % 16;
		header.resize(16, 0u8);

		let mut packet = vec![0u8; 32 + len + padding + 16];
		self.encoder.encrypt(
			&mut RefReadBuffer::new(&header), 
			&mut RefWriteBuffer::new(&mut packet), 
			false
		).expect("buffers have the right size; qed");

		update_mac(&mut self.egress_mac, &mut self.mac_encoder, H128::from(&packet[0..16]));
		self.egress_mac.clone().finalize(&mut packet[16..32]);
		self.encoder.encrypt(
			&mut RefReadBuffer::new(&item.data),
			&mut RefWriteBuffer::new(&mut packet[32..32 + len]),
			padding == 0
		).expect("buffers have the right size; qed");

		if padding != 0 {
			let pad = [0u8; 16];
			self.encoder.encrypt(
				&mut RefReadBuffer::new(&pad[0..padding]),
				&mut RefWriteBuffer::new(&mut packet[(32 + len)..(32 + len + padding)]),
				true
			).expect("buffers have the right size; qed");
		}

		self.egress_mac.update(&packet[32..(32 + len + padding)]);
		update_mac_with_empty_seed(&mut self.egress_mac, &mut self.mac_encoder);
		self.egress_mac.clone().finalize(&mut packet[(32 + len + padding)..]);
		dst.extend_from_slice(&packet);
		Ok(())
	}
}

impl Decoder for Codec {
	type Item = Packet;
	type Error = io::Error;

	fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
		let payload_info = match self.decode_state {
			DecodeState::Payload(info) => info,
			DecodeState::Header => {	
				if src.len() < ENCRYPTED_HEADER_LEN {
					return Ok(None);
				}

				let raw_header = src.split_to(ENCRYPTED_HEADER_LEN);
				update_mac(&mut self.ingress_mac, &mut self.mac_encoder, H128::from(&raw_header[0..16]));
				let mac = &raw_header[16..];

				let mut expected = H256::default();
				self.ingress_mac.clone().finalize(&mut expected);
				if mac != &expected[0..16] {
					return Err(io::Error::new(io::ErrorKind::Other, "Codec::decode failed"));
				}

				let mut hdec = H128::default();
				self.decoder.decrypt(
					&mut RefReadBuffer::new(&raw_header[0..16]),
					&mut RefWriteBuffer::new(&mut hdec),
					false
				).expect("buffers have the right size; qed");


				let payload_len = (((((hdec[0] as u32) << 8) + (hdec[1] as u32)) << 8) + (hdec[2] as u32)) as usize;
				let header_rlp = Rlp::new(&hdec[3..6]);
				let protocol_id = header_rlp.val_at::<u16>(0)
					.map_err(|_| io::Error::new(io::ErrorKind::Other, "Codec::decode failed"))?;

				let padding = (16 - (payload_len % 16)) % 16;
				let full_len= payload_len + padding + 16;

				PayloadInfo {
					protocol_id,
					len: payload_len,
					full_len,
				}
			},
		};

		self.decode_state = DecodeState::Payload(payload_info);

		if src.len() < payload_info.full_len {
			return Ok(None);
		}

		let raw_payload = src.split_to(payload_info.full_len);
		self.ingress_mac.update(&raw_payload[0..payload_info.full_len - 16]);
		update_mac_with_empty_seed(&mut self.ingress_mac, &mut self.mac_encoder);
		let mac = &raw_payload[payload_info.full_len - 16..];
		let mut expected = H128::default();
		self.ingress_mac.clone().finalize(&mut expected);
		if mac != &expected[..] {
			return Err(io::Error::new(io::ErrorKind::Other, "Codec::decode failed"));
		}

		let mut packet = vec![0u8; payload_info.len];
		let mut pad_buf = [0u8; 16];
		self.decoder.decrypt(
			&mut RefReadBuffer::new(&raw_payload[0..payload_info.len]), 
			&mut RefWriteBuffer::new(&mut packet),
			false
		).expect("buffers have the right size; qed");
		self.decoder.decrypt(
			&mut RefReadBuffer::new(&raw_payload[payload_info.len..payload_info.full_len - 16]),
			&mut RefWriteBuffer::new(&mut pad_buf),
			false
		).expect("buffers have the right size; qed");

		let packet = Packet {
			protocol: payload_info.protocol_id,
			data: packet,
		};

		self.decode_state = DecodeState::Header;

		Ok(Some(packet))
	}
}

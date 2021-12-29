use zeronet_cryptography::Error;
use serde::Serialize;

pub mod zeronet_formatter;

pub trait Sign: Sized + Serialize {
	/// Sign the struct with a private key using the default algorithm
	fn sign(self, key: &str) -> Result<Self, Error>;
	/// Sign the struct with a non-default signing algorithm
	fn sign_with<F: FnOnce(Vec<u8>) -> Result<String, Error> + Sized>(self, signer: F) -> Result<Self, Error>;
}

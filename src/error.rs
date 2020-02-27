use base64::DecodeError;
use secp256k1::Error as SecpError;

#[derive(Debug)]
pub enum Error {
	DecodeSignatureFailure,
	RecoveryIdFailure,
	RecoverableSignatureFailure,
	MessageFailure,
	PublicKeyFailure,
	AddressMismatch(String),
	PrivateKeyFailure,
}

impl From<DecodeError> for Error {
	fn from(_: DecodeError) -> Error {
		Error::DecodeSignatureFailure
	}
}

impl From<SecpError> for Error {
	fn from(error: SecpError) -> Error {
		match error {
			SecpError::InvalidRecoveryId => Error::RecoveryIdFailure,
			SecpError::InvalidSignature => Error::RecoverableSignatureFailure,
			SecpError::InvalidMessage => Error::MessageFailure,
			SecpError::InvalidPublicKey => Error::PublicKeyFailure,
			_ => Error::RecoverableSignatureFailure,
		}
	}
}

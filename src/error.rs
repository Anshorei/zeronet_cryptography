use base64::DecodeError;
use secp256k1::Error as SecpError;
use thiserror::Error;

#[derive(Error, Debug, Eq, PartialEq)]
pub enum CryptError {
  #[error("Failed to decode signature")]
  DecodeSignatureFailure,
  #[error("Failed to recover ID")]
  RecoveryIdFailure,
  #[error("Failed to recover signature")]
  RecoverableSignatureFailure,
  #[error("Something wrong with the message")]
  MessageFailure,
  #[error("Public key somethng")]
  PublicKeyFailure,
  #[error("Address mismatch ({0})")]
  AddressMismatch(String),
  #[error("Private key failure")]
  PrivateKeyFailure,
}

impl From<DecodeError> for CryptError {
  fn from(_: DecodeError) -> CryptError {
    CryptError::DecodeSignatureFailure
  }
}

impl From<SecpError> for CryptError {
  fn from(error: SecpError) -> CryptError {
    match error {
      SecpError::InvalidRecoveryId => CryptError::RecoveryIdFailure,
      SecpError::InvalidSignature => CryptError::RecoverableSignatureFailure,
      SecpError::InvalidMessage => CryptError::MessageFailure,
      SecpError::InvalidPublicKey => CryptError::PublicKeyFailure,
      _ => CryptError::RecoverableSignatureFailure,
    }
  }
}

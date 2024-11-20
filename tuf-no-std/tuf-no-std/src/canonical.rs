#[derive(Debug)]
pub enum EncodingError {
    BufferTooSmall,
}

/// Trait used to abstract files being encoded canonically.
pub trait EncodeCanonically {
    /// Encodes the file canonically.
    /// It is important to note that this **does never** encode the
    /// `signatures` field, as it is not used as part of the canonical encoding.
    fn encode_canonically<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], EncodingError>;
}

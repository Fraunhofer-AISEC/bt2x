use crate::role::TufSignature;
#[cfg(feature = "der")]
use tuf_no_std_der::SignatureRef;

#[cfg(feature = "der")]
impl<'a> TufSignature for SignatureRef<'a> {
    fn raw_sig(&self) -> &[u8] {
        self.sig.as_bytes().unwrap()
    }

    fn keyid(&self) -> [u8; 32] {
        self.keyid
            .as_bytes()
            .ok_or(())
            .and_then(|keyid| TryFrom::try_from(keyid).map_err(|_| ()))
            .unwrap()
    }
}

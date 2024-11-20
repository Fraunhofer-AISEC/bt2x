use crate::artifact::source::ArtifactSource;
use crate::error::Bt2XError;
use async_trait::async_trait;
use sigstore::cosign::bundle::SignedArtifactBundle;
use sigstore::crypto::CosignVerificationKey;
use std::fs::read;
use url::Url;

pub struct BundleSource {}

#[async_trait(? Send)]
impl ArtifactSource<Vec<u8>, url::Url> for BundleSource {
    async fn get_artifact(&mut self, identifier: &Url) -> Result<Vec<u8>, Bt2XError> {
        self.get_blob(identifier)
    }

    #[allow(unused_variables)]
    async fn get_bundle(&mut self, identifier: &Url) -> Result<Vec<u8>, Bt2XError> {
        unimplemented!()
    }
}

impl BundleSource {
    fn get_blob(&mut self, url: &Url) -> Result<Vec<u8>, Bt2XError> {
        if url.scheme() == "file" {
            let data = read(url.to_file_path().expect("failed get file path from url"))?;
            return Ok(data);
        }
        unimplemented!("only supports files for now.")
    }
    pub fn get_bundle(
        &mut self,
        url: &Url,
        rekor_pub_key: &CosignVerificationKey,
    ) -> Result<SignedArtifactBundle, Bt2XError> {
        let data = if url.scheme() == "file" {
            read(url.to_file_path().expect("failed get file path from url"))?
        } else {
            unimplemented!("only supports files for now");
        };
        let bundle = SignedArtifactBundle::new_verified(
            String::from_utf8(data).unwrap().as_str(),
            rekor_pub_key,
        )
        .unwrap();

        Ok(bundle)
    }
}

pub struct BlobBundle {
    pub data: Vec<u8>,
    pub bundle: SignedArtifactBundle,
}

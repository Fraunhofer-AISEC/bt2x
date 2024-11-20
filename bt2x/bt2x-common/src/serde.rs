use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{base64::Base64, hex::Hex, serde_as};

use base64::{engine::general_purpose::STANDARD as B64StandardEngine, Engine};
use olpc_cjson::CanonicalFormatter;
use serde::de::DeserializeOwned;
use sigstore::cosign::bundle::{Payload, SignedArtifactBundle};
use sigstore::rekor::models::LogEntry;

use crate::error::Bt2XError;

#[serde_as]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CosignBundle {
    #[serde_as(as = "Base64")]
    base64_signature: Vec<u8>,
    #[serde_as(as = "Base64")]
    cert: Vec<u8>,
    rekor_bundle: RekorBundle,
}

#[serde_as]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RekorBundle {
    #[serde_as(as = "Base64")]
    pub signed_entry_timestamp: Vec<u8>,
    pub payload: BundlePayload,
}

#[serde_as]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundlePayload {
    #[serde_as(as = "Base64")]
    pub body: Vec<u8>,
    pub integrated_time: u64,
    pub log_index: u64,
    #[serde_as(as = "Hex")]
    #[serde(rename = "logID")]
    pub log_id: [u8; 32],
}

#[serde_as]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CompactRekorBundle {
    #[serde_as(as = "Base64")]
    pub signed_entry_timestamp: Vec<u8>,
    #[serde(
        serialize_with = "serialize_b64_canonical_json",
        deserialize_with = "deserialize_b64_canonical_json"
    )]
    pub payload: CompactBundlePayload,
}

#[serde_as]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompactBundlePayload {
    //#[serde_as(as = "Base64")]
    #[serde(
        serialize_with = "serialize_b64_canonical_json",
        deserialize_with = "deserialize_b64_canonical_json"
    )]
    pub body: CompactPayloadBody,

    pub integrated_time: u64,
    pub log_index: u64,
    #[serde_as(as = "Hex")]
    #[serde(rename = "logID")]
    pub log_id: [u8; 32],
}

#[serde_as]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompactPayloadBody {
    pub api_version: ApiVersion,
    #[serde(flatten)]
    pub spec: Spec,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", content = "spec")]
pub enum Spec {
    #[serde(rename = "hashedrekord")]
    HashedRekord {
        data: HashedRekordData,
        signature: Signature,
    },
}

#[derive(Deserialize, Serialize)]
pub struct HashedRekordData {
    hash: Hash,
}

#[serde_as]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<SignatureFormat>,
    #[serde_as(as = "Base64")]
    pub content: Vec<u8>,
    pub public_key: PublicKey,
}

#[serde_as]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKey {
    #[serde_as(as = "Base64")]
    pub content: Vec<u8>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureFormat {
    Pgp,
    Minisign,
    X509,
    Ssh,
}

#[serde_as]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase", tag = "algorithm", content = "value")]
pub enum Hash {
    Sha256(#[serde_as(as = "Hex")] [u8; 32]),
}

#[derive(Deserialize, Serialize)]
pub enum ApiVersion {
    #[serde(rename = "0.0.1")]
    ZeroZeroOne,
}

fn serialize_b64_canonical_json<S, T>(payload: &T, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    payload
        .serialize(&mut ser)
        .map_err(|err| serde::ser::Error::custom(format!("{err}")))
        .map(|_| B64StandardEngine.encode(buf))
        .and_then(|encoded| s.serialize_str(&encoded))
}

fn deserialize_b64_canonical_json<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    let buf = String::deserialize(deserializer)?;
    B64StandardEngine
        .decode(buf)
        .map_err(|err| err.to_string())
        .and_then(|decoded| serde_json::from_slice::<T>(&decoded).map_err(|e| e.to_string()))
        .map_err(serde::de::Error::custom)
}

impl From<SignedArtifactBundle> for CompactRekorBundle {
    fn from(value: SignedArtifactBundle) -> Self {
        CompactRekorBundle {
            signed_entry_timestamp: B64StandardEngine
                .decode(value.rekor_bundle.signed_entry_timestamp)
                .expect("failed to decode the SET"),
            payload: value.rekor_bundle.payload.into(),
        }
    }
}

impl CosignBundle {
    pub fn from_signing_material_and_log_entry(
        sig: &[u8],
        cert_pem: &[u8],
        log_entry: &LogEntry,
    ) -> Result<CosignBundle, Bt2XError> {
        Ok(CosignBundle {
            base64_signature: (B64StandardEngine.encode(sig)).into_bytes(),
            cert: B64StandardEngine.encode(cert_pem).into_bytes(),
            rekor_bundle: RekorBundle {
                signed_entry_timestamp: log_entry
                    .verification
                    .signed_entry_timestamp
                    .clone()
                    .into_bytes(),
                payload: BundlePayload {
                    body: serde_json::to_vec(&log_entry.body)
                        .map_err(Bt2XError::JsonSerializationError)
                        .map(|v| B64StandardEngine.encode(v).into_bytes())?,
                    integrated_time: log_entry.integrated_time as u64,
                    log_index: log_entry.log_index as u64,
                    log_id: (hex::decode(&log_entry.log_i_d)
                        .map_err(Bt2XError::HexDecodingError)?)
                    .try_into()
                    .map_err(|_| {
                        Bt2XError::InternalError("could not convert slice to Array".to_string())
                    })?,
                },
            },
        })
    }
}

impl From<Payload> for CompactBundlePayload {
    fn from(value: Payload) -> Self {
        CompactBundlePayload {
            body: serde_json::from_slice(serde_json::to_vec(&value.body).unwrap().as_slice())
                .unwrap(),
            integrated_time: value.integrated_time as u64,
            log_index: value.log_index as u64,
            log_id: <[u8; 32]>::try_from(
                hex::decode(value.log_id).expect("failed to decode the log ID"),
            )
            .expect("invalid length"),
        }
    }
}

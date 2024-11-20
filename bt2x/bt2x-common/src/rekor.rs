pub use sigstore::rekor::apis::configuration::Configuration;
use sigstore::rekor::apis::entries_api::{CreateLogEntryError, SearchLogQueryError};
use sigstore::rekor::apis::index_api::SearchIndexError;
use sigstore::rekor::apis::tlog_api::{GetLogInfoError, GetLogProofError};
use sigstore::rekor::apis::{entries_api, index_api, pubkey_api, tlog_api, Error};
use sigstore::rekor::models::{
    ConsistencyProof, LogEntry, LogInfo, ProposedEntry, SearchIndex, SearchLogQuery,
};

pub enum RekorEntryIdentifier {
    LogIndex(u64),
    Uuid(String),
}

impl From<u64> for RekorEntryIdentifier {
    fn from(val: u64) -> RekorEntryIdentifier {
        RekorEntryIdentifier::LogIndex(val)
    }
}

impl From<&str> for RekorEntryIdentifier {
    fn from(val: &str) -> RekorEntryIdentifier {
        RekorEntryIdentifier::Uuid(val.to_string())
    }
}

#[derive(Debug)]
pub struct RekorClient {
    config: Configuration,
}

impl RekorClient {
    pub async fn get_log_entry(
        &self,
        identifier: impl Into<RekorEntryIdentifier>,
    ) -> Result<LogEntry, Box<dyn std::error::Error>> {
        match identifier.into() {
            RekorEntryIdentifier::LogIndex(log_index) => {
                if log_index == 0 {
                    return Err("log index is always > 0".to_string().into());
                }
                entries_api::get_log_entry_by_index(&self.config, log_index as i32)
                    .await
                    .map_err(|err| err.into())
            }
            RekorEntryIdentifier::Uuid(uiid) => {
                entries_api::get_log_entry_by_uuid(&self.config, uiid.as_str())
                    .await
                    .map_err(|err| err.into())
            }
        }
    }

    pub async fn create_log_entry(
        &self,
        proposed_entry: ProposedEntry,
    ) -> Result<LogEntry, Error<CreateLogEntryError>> {
        entries_api::create_log_entry(&self.config, proposed_entry).await
    }

    pub async fn search_log_query(
        &self,
        query: SearchLogQuery,
    ) -> Result<String, Error<SearchLogQueryError>> {
        entries_api::search_log_query(&self.config, query).await
    }

    pub async fn get_log_info(&self) -> Result<LogInfo, Error<GetLogInfoError>> {
        tlog_api::get_log_info(&self.config).await
    }

    pub async fn get_log_proof(
        &self,
        last_size: usize,
        first_size: Option<usize>,
        tree_id: Option<&str>,
    ) -> Result<ConsistencyProof, Error<GetLogProofError>> {
        let first_size = first_size.map(|i| i.to_string());
        tlog_api::get_log_proof(
            &self.config,
            last_size as i32,
            first_size.as_deref(),
            tree_id,
        )
        .await
    }

    pub async fn search_index(
        &self,
        query: SearchIndex,
    ) -> Result<Vec<String>, Error<SearchIndexError>> {
        index_api::search_index(&self.config, query).await
    }

    pub async fn get_pubkey(
        &self,
        tree_id: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        pubkey_api::get_public_key(&self.config, tree_id)
            .await
            .map_err(|err| err.into())
    }
    pub fn new(config: Configuration) -> Self {
        RekorClient { config }
    }
}

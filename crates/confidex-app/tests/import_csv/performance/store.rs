use confidex_storage::*;

pub struct Measured<'a, S> {
    pub inner: &'a mut S,
    pub commit_ms: f64,
}
macro_rules! forward {
    ($name:ident ($($arg:ident: $kind:ty),*) -> $output:ty) => {
        async fn $name(&mut self, $($arg: $kind),*) -> Result<$output, Error> {
            self.inner.$name($($arg),*).await
        }
    };
}
impl<S: Store> Store for Measured<'_, S> {
    forward!(branch_heads(vault: VaultId, after: Option<&Head>, tag: Option<&str>) -> Vec<Head>);
    forward!(publish_branches(vault: VaultId, commit: &SyncCommit) -> ());
    forward!(rename(vault: VaultId, expected: &str, name: &str) -> ());
    forward!(clear_records(vault: VaultId) -> ());
    forward!(remove(vault: VaultId) -> ());
    forward!(snapshot(vault: VaultId) -> Snapshot);
    forward!(restore(snapshot: &Snapshot) -> ());
    forward!(vaults() -> Vec<VaultInfo>);
    forward!(vault(id: VaultId) -> StoredVault);
    forward!(create(vault: &StoredVault) -> ());
    forward!(heads(vault: VaultId, after: Option<RecordId>) -> Vec<Head>);
    forward!(tagged_heads(vault: VaultId, tag: &str, after: Option<RecordId>) -> Vec<Head>);
    forward!(head(vault: VaultId, record: RecordId) -> Option<Head>);
    forward!(object(vault: VaultId, revision: RevisionId) -> Vec<u8>);
    forward!(append(vault: VaultId, head: &Head, expected: Option<RevisionId>, wire: &[u8], tags: &[String]) -> ());
    forward!(sync_state(vault: VaultId) -> Option<Vec<u8>>);
    forward!(sync_commit(vault: VaultId, commit: &SyncCommit) -> ());
    async fn batch_commit(&mut self, vault: VaultId, commit: &BatchCommit) -> Result<(), Error> {
        let started = super::timing::now();
        let result = self.inner.batch_commit(vault, commit).await;
        self.commit_ms += super::timing::now() - started;
        result
    }
}

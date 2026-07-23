use anyhow::Result;

pub struct E01Reader;

impl E01Reader {
    pub fn open(_path: &str) -> Result<Self> {
        anyhow::bail!("E01Reader not yet implemented - waiting for valid libewf binding")
    }

    pub fn get_metadata(&self) -> Result<E01Metadata> {
        anyhow::bail!("Not implemented")
    }

    pub fn extract_artifacts(&self) -> Result<Vec<u8>> {
        anyhow::bail!("Not implemented")
    }
}

pub struct E01Metadata {
    pub format: String,
    pub total_sectors: u64,
    pub sector_size: u32,
}

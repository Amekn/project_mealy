use mealy_core::{MealyError, Result};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct MealyPaths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
}

impl MealyPaths {
    pub fn resolve() -> Result<Self> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| MealyError::Config("could not resolve user config directory".into()))?
            .join("mealy");
        let data_dir = dirs::data_dir()
            .ok_or_else(|| MealyError::Config("could not resolve user data directory".into()))?
            .join("mealy");
        let cache_dir = dirs::cache_dir()
            .ok_or_else(|| MealyError::Config("could not resolve user cache directory".into()))?
            .join("mealy");

        Ok(Self {
            config_dir,
            data_dir,
            cache_dir,
        })
    }
}

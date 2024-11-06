use thiserror::Error;
#[derive(Debug, Error)]
pub enum NichanTextGeneratorError {
    #[error("not apply dice command")]
    NotApplyDiceCommand,
}
pub type NichanTextGeneratorResult<T> = std::result::Result<T, NichanTextGeneratorError>;

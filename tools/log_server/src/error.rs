use crate::input::DbValue;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    ModelNotFound(String),
    FieldNotFound(String),
    InvalidValue(String),
    InvalidJson(String),
    Rusqlite(rusqlite::Error),
    Chrono(chrono::ParseError),
    Io(std::io::Error),
}
impl Error {
    pub fn invalid_value<T>(expected: &str, field: &T, value: &DbValue) -> Self
    where
        T: crate::field::Field,
    {
        Error::InvalidValue(format!(
            "Expected {} in {}, got {:?}",
            expected,
            field.name(),
            value
        ))
    }
    pub fn invalid_json<T>(expected: &str, field: &T, value: &serde_json::Value) -> Self
    where
        T: crate::field::Field,
    {
        Error::InvalidJson(format!(
            "Expected {} in {}, got {:?}",
            expected,
            field.name(),
            value
        ))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Rusqlite(err) => Some(err),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(err: rusqlite::Error) -> Error {
        Error::Rusqlite(err)
    }
}
impl From<chrono::ParseError> for Error {
    fn from(err: chrono::ParseError) -> Error {
        Error::Chrono(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::Io(err)
    }
}

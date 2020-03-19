pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
pub struct Error {
    msg: String,
    sub: Option<SubError>,
}
#[derive(Debug)]
pub enum SubError {
    Io(std::io::Error),
    Ssh(ssh2::Error),
}
impl Error {
    pub fn msg<T, S: Into<String>>(msg: S) -> Result<T> {
        Err(Error {
            msg: msg.into(),
            sub: None,
        })
    }
    pub fn io<T, S: Into<String>>(msg: S, error: std::io::Error) -> Result<T> {
        Err(Error {
            msg: msg.into(),
            sub: Some(SubError::Io(error)),
        })
    }
    pub fn ssh<T, S: Into<String>>(msg: S, error: ssh2::Error) -> Result<T> {
        Err(Error {
            msg: msg.into(),
            sub: Some(SubError::Ssh(error)),
        })
    }
}

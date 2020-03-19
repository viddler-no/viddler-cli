// `error_chain!` can recurse deeply
#![recursion_limit = "1024"]

mod app;
mod aws;
mod cli;
mod cli_app;
mod docker;
mod git;
mod project;
mod project_path;
mod server;
mod utils;
mod workspace;
mod wp;

mod jitsi_env_file;
mod jitsi_project;

// (Currently) Superseded by ssh which comes with sftp
// nice cli, user handling. In some sense larger attack
// area though.
//mod wp_cli_client;

#[macro_use]
extern crate failure_derive;

mod er {
    use failure::{Error, Fail};
    use std::fmt;

    pub type Result<T> = std::result::Result<T, Error>;

    pub trait FailExt {
        fn err<T>(self) -> Result<T>;
        fn error(self) -> Error;
    }
    impl<F: Fail> FailExt for F {
        fn err<T>(self) -> Result<T> {
            Err(Error::from(self))
        }
        fn error(self) -> Error {
            Error::from(self)
        }
    }

    /// Quick way to create a custom error with
    /// a string message
    pub fn error<S>(msg: S) -> Custom
    where
        S: Into<String>,
    {
        Custom::msg(msg)
    }

    pub fn err<S, T>(msg: S) -> Result<T>
    where
        S: Into<String>,
    {
        Err(Custom::msg(msg).into())
    }

    #[derive(Debug, Fail)]
    pub struct Custom {
        msg: String,
    }
    impl Custom {
        pub fn msg<S: Into<String>>(msg: S) -> Self {
            Custom { msg: msg.into() }
        }
    }
    impl fmt::Display for Custom {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "Error: {}", self.msg)
        }
    }

    // Ssh2 error
    #[derive(Debug, Fail)]
    pub struct Ssh {
        msg: Option<String>,
        #[fail(cause)]
        e: ssh2::Error,
    }
    impl Ssh {
        pub fn e(e: ssh2::Error) -> Self {
            Ssh { msg: None, e }
        }
        pub fn msg<S: Into<String>>(msg: S, e: ssh2::Error) -> Self {
            Ssh {
                msg: Some(msg.into()),
                e,
            }
        }
    }
    impl fmt::Display for Ssh {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match &self.msg {
                Some(msg) => write!(f, "{}: {:?}", msg, self.e),
                None => {
                    write!(f, "Ssh error: {:?}", self.e)
                    /*
                    // I think codes depend on context, like session or sftp
                    match self.e.code() {

                    }*/
                }
            }
        }
    }
    // Io error
    #[derive(Debug, Fail)]
    pub struct Io {
        msg: Option<String>,
        #[fail(cause)]
        e: std::io::Error,
    }
    impl Io {
        pub fn e(e: std::io::Error) -> Self {
            Io { msg: None, e }
        }
        pub fn msg<S: Into<String>>(msg: S, e: std::io::Error) -> Self {
            Io {
                msg: Some(msg.into()),
                e,
            }
        }
    }
    impl fmt::Display for Io {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match &self.msg {
                Some(msg) => write!(f, "{}: {:?}", msg, self.e),
                None => write!(f, "Io error: {:?}", self.e),
            }
        }
    }
    impl From<std::io::Error> for Io {
        fn from(e: std::io::Error) -> Self {
            Io::e(e)
        }
    }

    // Walkdir error
    #[derive(Debug, Fail)]
    pub struct Walkdir {
        msg: Option<String>,
        #[fail(cause)]
        e: walkdir::Error,
    }
    impl Walkdir {
        pub fn e(e: walkdir::Error) -> Error {
            Error::from(Walkdir { msg: None, e })
        }
        pub fn msg<S: Into<String>>(msg: S, e: walkdir::Error) -> Error {
            Error::from(Walkdir {
                msg: Some(msg.into()),
                e,
            })
        }
    }
    impl fmt::Display for Walkdir {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match &self.msg {
                Some(msg) => write!(f, "{}: {:?}", msg, self.e),
                None => write!(f, "Walkdir error: {:?}", self.e),
            }
        }
    }

    // MyLibError (mysql-utils)
    /*
    #[derive(Debug, Fail)]
    pub struct MyLib {
        msg: Option<String>,
        #[fail(cause)]
        e: mysql_utils::er::MyLibError,
    }
    impl MyLib {
        pub fn e(e: mysql_utils::er::MyLibError) -> Self {
            MyLib { msg: None, e }
        }
        pub fn msg<S: Into<String>>(msg: S, e: mysql_utils::er::MyLibError) -> Self {
            MyLib {
                msg: Some(msg.into()),
                e,
            }
        }
    }
    impl fmt::Display for MyLib {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match &self.msg {
                Some(msg) => write!(f, "{}: {:?}", msg, self.e),
                None => write!(f, "MyLib error: {:?}", self.e),
            }
        }
    }*/

    #[derive(Debug, Fail)]
    pub struct SerdeJson {
        msg: Option<String>,
        #[fail(cause)]
        e: serde_json::Error,
    }
    impl SerdeJson {
        pub fn e(e: serde_json::Error) -> Self {
            SerdeJson { msg: None, e }
        }
        pub fn msg<S: Into<String>>(msg: S, e: serde_json::Error) -> Self {
            SerdeJson {
                msg: Some(msg.into()),
                e,
            }
        }
    }
    impl fmt::Display for SerdeJson {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match &self.msg {
                Some(msg) => write!(f, "{}: {:?}", msg, self.e),
                None => write!(f, "SerdeJson error: {:?}", self.e),
            }
        }
    }

    //fn to_io_err<E: std::fmt::Debug>(rusoto_error: rusoto_core::RusotoError<E>) -> io::Error {

    // Since rusoto takes a parameter, simplifying to getting the debug string
    #[derive(Debug, Fail)]
    pub struct Rusoto {
        msg: Option<String>,
        e: String,
    }
    impl Rusoto {
        pub fn e<E: std::fmt::Debug>(e: rusoto_core::RusotoError<E>) -> Self {
            Rusoto {
                msg: None,
                e: format!("{:?}", e),
            }
        }
        pub fn msg<S: Into<String>, E: std::fmt::Debug>(
            msg: S,
            e: rusoto_core::RusotoError<E>,
        ) -> Self {
            Rusoto {
                msg: Some(msg.into()),
                e: format!("{:?}", e),
            }
        }
    }
    impl fmt::Display for Rusoto {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match &self.msg {
                Some(msg) => write!(f, "{}: {:?}", msg, self.e),
                None => write!(f, "Rusoto error: {:?}", self.e),
            }
        }
    }
}

fn main() {
    if let Err(ref e) = cli_app::run() {
        use std::io::Write;
        let stderr = &mut ::std::io::stderr();
        let errmsg = "Error writing to stderr";

        writeln!(stderr, "error: {}", e).expect(errmsg);

        let mut fail = e.as_fail();

        // Not sure which/what makes sense
        if let Some(bt) = fail.cause().and_then(|cause| cause.backtrace()) {
            println!("{}", bt)
        } else {
            println!("{}", e.backtrace())
        }

        while let Some(cause) = fail.cause() {
            println!("{}", cause);

            // Make `fail` the reference to the cause of the previous fail, making the
            // loop "dig deeper" into the cause chain.
            fail = cause;
        }

        ::std::process::exit(1);
    }
}

use actix_web::{HttpResponse, http::StatusCode};


pub struct DateVal(chrono::NaiveDate);
impl DateVal {
    // Could also implement some ToString, Into<String> ? Not sure which makes sense
    pub fn format(&self) -> String {
        self.0.format("%Y-%m-%d").to_string()
    }
    pub fn try_from(from: &str) -> crate::error::Result<Self> {
        let date = chrono::NaiveDate::parse_from_str(from, "%Y-%m-%d")?;
        Ok(DateVal(date))
    }
}

impl std::convert::TryFrom<&str> for DateVal {
    type Error = crate::error::Error;
    fn try_from(from: &str) -> std::result::Result<Self, Self::Error> {
        DateVal::try_from(from)
    }
}

pub struct DateTimeVal(chrono::NaiveDateTime);
impl DateTimeVal {
    // Could also implement some ToString, Into<String> ? Not sure which makes sense
    pub fn format(&self) -> String {
        self.0.format("%Y-%m-%d  %H:%M:%S").to_string()
    }
    pub fn try_from(from: &str) -> crate::error::Result<Self> {
        let datetime = chrono::NaiveDateTime::parse_from_str(from, "%Y-%m-%d  %H:%M:%S")?;
        Ok(DateTimeVal(datetime))
    }
}

impl std::convert::TryFrom<&str> for DateTimeVal {
    type Error = crate::error::Error;
    fn try_from(from: &str) -> std::result::Result<Self, Self::Error> {
        DateTimeVal::try_from(from)
    }
}

pub fn html_resp(html: String) -> HttpResponse {
    HttpResponse::build(StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body(html)
}

pub fn json_resp<T>(json: T) -> HttpResponse
where
    T: serde::Serialize,
{
    let json = serde_json::to_string_pretty(&json).unwrap_or("Json error".into());
    HttpResponse::build(StatusCode::OK)
        .content_type("application/json; charset=utf-8")
        .body(json)
}

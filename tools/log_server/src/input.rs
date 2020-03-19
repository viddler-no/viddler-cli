use crate::utils::{DateTimeVal, DateVal};
use rusqlite::ToSql;

#[derive(Debug)]
pub enum DbValue {
    Text(String),
    Int(i64),
    Bool(bool),
    Date(String),
    DateTime(String),
}

impl DbValue {
    pub fn to_rusqlite(&self) -> &dyn ToSql {
        match self {
            DbValue::Text(value) => (value as &dyn ToSql),
            DbValue::Int(value) => (value as &dyn ToSql),
            DbValue::Bool(value) => (value as &dyn ToSql),
            DbValue::Date(value) => (value as &dyn ToSql),
            DbValue::DateTime(value) => (value as &dyn ToSql),
        }
    }
}

impl From<String> for DbValue {
    fn from(from: String) -> Self {
        DbValue::Text(from)
    }
}
impl From<&str> for DbValue {
    fn from(from: &str) -> Self {
        DbValue::Text(from.to_owned())
    }
}
impl From<i32> for DbValue {
    fn from(from: i32) -> Self {
        DbValue::Int(from as i64)
    }
}
impl From<i64> for DbValue {
    fn from(from: i64) -> Self {
        DbValue::Int(from)
    }
}
impl From<bool> for DbValue {
    fn from(from: bool) -> Self {
        DbValue::Bool(from)
    }
}
impl From<DateVal> for DbValue {
    fn from(from: DateVal) -> Self {
        DbValue::Date(from.format())
    }
}
impl From<DateTimeVal> for DbValue {
    fn from(from: DateTimeVal) -> Self {
        DbValue::DateTime(from.format())
    }
}

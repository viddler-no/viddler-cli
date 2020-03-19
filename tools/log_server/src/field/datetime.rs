use crate::error::{Error, Result};
use crate::field::{DbField, DbFieldType, Field};
use crate::input::DbValue;

pub struct DateTimeField {
    pub db_field: DbField,
}
impl DateTimeField {
    pub fn date(name: impl Into<String>) -> Box<Self> {
        Box::new(DateTimeField {
            db_field: DbField {
                name: name.into(),
                field_type: DbFieldType::DateTime,
                primary_key: false,
                null: false,
                auto_increment: false,
            },
        })
    }
}
impl Field for DateTimeField {
    fn db_field(&self) -> &DbField {
        &self.db_field
    }
    fn validate_value(&self, value: &DbValue) -> Result<()> {
        match value {
            DbValue::DateTime(_) => Ok(()),
            _ => Err(Error::invalid_value("datetime", self, value)),
        }
    }
    fn render_html(&self, b: &mut String, row: &rusqlite::Row, i: usize) -> Result<()> {
        // Should date be parsed at this point?
        let v: String = row.get(i)?;
        b.push_str(&v);
        Ok(())
    }
    fn json_to_input(&self, value: &serde_json::Value) -> Result<DbValue> {
        match value {
            serde_json::Value::String(v) => {
                // Could be better with InvalidJson error
                // This serves to validate the date
                let date = chrono::NaiveDateTime::parse_from_str(v, "%Y-%m-%d  %H:%M:%S")?;
                Ok(DbValue::DateTime(
                    date.format("%Y-%m-%d %H:%M:%S").to_string(),
                ))
            }
            _ => Err(Error::invalid_json("string", self, value)),
        }
    }
}

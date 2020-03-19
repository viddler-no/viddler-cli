use crate::error::{Error, Result};
use crate::field::{DbField, DbFieldType, Field};
use crate::input::DbValue;

pub struct DateField {
    pub db_field: DbField,
}
impl DateField {
    pub fn date(name: impl Into<String>) -> Box<Self> {
        Box::new(DateField {
            db_field: DbField {
                name: name.into(),
                field_type: DbFieldType::Date,
                primary_key: false,
                null: false,
                auto_increment: false,
            },
        })
    }
}
impl Field for DateField {
    fn db_field(&self) -> &DbField {
        &self.db_field
    }
    fn validate_value(&self, value: &DbValue) -> Result<()> {
        match value {
            DbValue::Date(_) => Ok(()),
            _ => Err(Error::invalid_value("date", self, value)),
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
                let date = chrono::NaiveDate::parse_from_str(v, "%Y-%m-%d")?;
                Ok(DbValue::Date(date.format("%Y-%m-%d").to_string()))
            }
            _ => Err(Error::invalid_json("string", self, value)),
        }
    }
}

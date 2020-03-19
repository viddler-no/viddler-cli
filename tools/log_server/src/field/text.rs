use crate::error::{Error, Result};
use crate::field::{DbField, DbFieldType, Field};
use crate::input::DbValue;

pub struct TextField {
    pub db_field: DbField,
}
impl TextField {
    pub fn text(name: impl Into<String>) -> Box<Self> {
        Box::new(TextField {
            db_field: DbField {
                name: name.into(),
                field_type: DbFieldType::Text,
                primary_key: false,
                null: false,
                auto_increment: false,
            },
        })
    }
    pub fn primary(name: impl Into<String>) -> Box<Self> {
        Box::new(TextField {
            db_field: DbField {
                name: name.into(),
                field_type: DbFieldType::Text,
                primary_key: true,
                null: false,
                auto_increment: false,
            },
        })
    }
}

impl Field for TextField {
    fn db_field(&self) -> &DbField {
        &self.db_field
    }
    fn validate_value(&self, value: &DbValue) -> Result<()> {
        match value {
            DbValue::Text(_) => Ok(()),
            _ => Err(Error::invalid_value("text", self, value)),
        }
    }
    fn render_html(&self, b: &mut String, row: &rusqlite::Row, i: usize) -> Result<()> {
        let v: String = row.get(i)?;
        b.push_str(&v);
        Ok(())
    }
    fn json_to_input(&self, value: &serde_json::Value) -> Result<DbValue> {
        match value {
            serde_json::Value::String(v) => Ok(DbValue::Text(v.to_owned())),
            _ => Err(Error::invalid_json("string", self, value)),
        }
    }
}

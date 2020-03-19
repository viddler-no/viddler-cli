use crate::error::{Error, Result};
use crate::field::{DbField, DbFieldType, Field};
use crate::input::DbValue;

pub struct BoolField {
    pub db_field: DbField,
}
impl BoolField {
    pub fn boolean(name: impl Into<String>) -> Box<Self> {
        Box::new(BoolField {
            db_field: DbField {
                name: name.into(),
                field_type: DbFieldType::Bool,
                primary_key: false,
                null: false,
                auto_increment: false,
            },
        })
    }
}
impl Field for BoolField {
    fn db_field(&self) -> &DbField {
        &self.db_field
    }
    fn validate_value(&self, value: &DbValue) -> Result<()> {
        match value {
            DbValue::Bool(_) => Ok(()),
            _ => Err(Error::invalid_value("bool", self, value)),
        }
    }
    fn render_html(&self, b: &mut String, row: &rusqlite::Row, i: usize) -> Result<()> {
        let v: i32 = row.get(i)?;
        if v == 1 {
            b.push_str("true");
        } else if v == 0 {
            b.push_str("false");
        } else {
            b.push_str("");
        }
        Ok(())
    }
    fn json_to_input(&self, value: &serde_json::Value) -> Result<DbValue> {
        match value {
            serde_json::Value::Bool(v) => Ok(DbValue::Bool(*v)),
            _ => Err(Error::invalid_json("bool", self, value)),
        }
    }
}

use crate::error::{Error, Result};
use crate::field::{DbField, DbFieldType, Field};
use crate::input::DbValue;

/// A dedicated type for id field of INT AUTOINCREMENT PRIMARY KEY NOT NULL
pub struct IdField {
    pub db_field: DbField,
}
impl IdField {
    pub fn id() -> Box<Self> {
        Box::new(IdField {
            db_field: DbField {
                name: "id".into(),
                field_type: DbFieldType::Int,
                primary_key: true,
                null: false,
                auto_increment: true,
            },
        })
    }
}
impl Field for IdField {
    fn db_field(&self) -> &DbField {
        &self.db_field
    }
    fn validate_value(&self, value: &DbValue) -> Result<()> {
        match value {
            DbValue::Int(_) => Ok(()),
            _ => Err(Error::invalid_value("int", self, value)),
        }
    }
    fn render_html(&self, b: &mut String, row: &rusqlite::Row, i: usize) -> Result<()> {
        let v: i32 = row.get(i)?;
        b.push_str(&v.to_string());
        Ok(())
    }
    fn json_to_input(&self, value: &serde_json::Value) -> Result<DbValue> {
        match value {
            serde_json::Value::Number(v) => match v.as_i64() {
                Some(int) => Ok(DbValue::Int(int)),
                None => Err(Error::invalid_json("i64", self, value)),
            },
            _ => Err(Error::invalid_json("number", self, value)),
        }
    }
}

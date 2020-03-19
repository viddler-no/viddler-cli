use crate::error::{Error, Result};
use crate::field::{DbField, DbFieldType, Field};
use crate::input::DbValue;

pub struct IntField {
    pub db_field: DbField,
}
impl IntField {
    pub fn int(name: impl Into<String>) -> Box<Self> {
        Box::new(IntField {
            db_field: DbField {
                name: name.into(),
                field_type: DbFieldType::Int,
                primary_key: false,
                null: false,
                auto_increment: false,
            },
        })
    }
}
impl Field for IntField {
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

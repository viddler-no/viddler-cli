mod boolean;
mod date;
mod datetime;
mod id;
mod int;
mod text;

pub use boolean::BoolField;
pub use date::DateField;
pub use datetime::DateTimeField;
pub use id::IdField;
pub use int::IntField;
pub use text::TextField;

use crate::error::{Error, Result};
use crate::input::DbValue;

pub struct DbField {
    pub name: String,
    pub field_type: DbFieldType,
    pub auto_increment: bool,
    pub primary_key: bool,
    pub null: bool,
}

pub enum DbFieldType {
    Text,
    Int,
    Date,
    DateTime,
    Bool,
}

pub trait Field {
    fn render_html(&self, b: &mut String, row: &rusqlite::Row, i: usize) -> Result<()>;
    fn validate_value(&self, value: &DbValue) -> Result<()>;
    fn json_to_input(&self, value: &serde_json::Value) -> Result<DbValue>;
    fn db_field(&self) -> &DbField;
    fn name(&self) -> String {
        self.db_field().name.clone()
    }
    fn select_expr(&self) -> String {
        self.db_field().select_expr()
    }
    fn label(&self) -> String {
        self.name()
    }
}

impl DbField {
    pub fn select_expr(&self) -> String {
        self.name.clone()
    }

    pub fn create_def(&self) -> String {
        let mut def = String::from(&self.name);
        match self.field_type {
            DbFieldType::Text => def.push_str(" TEXT"),
            DbFieldType::Int => def.push_str(" INTEGER"),
            DbFieldType::Bool => def.push_str(" INTEGER"),
            DbFieldType::Date => def.push_str(" TEXT"),
            DbFieldType::DateTime => def.push_str(" TEXT"),
        }
        if self.primary_key {
            def.push_str(" PRIMARY KEY");
        }
        if self.auto_increment {
            def.push_str(" AUTOINCREMENT");
        }
        if !self.auto_increment && !self.null {
            def.push_str(" NOT NULL");
        }
        def
    }
}

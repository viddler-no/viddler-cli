use indexmap::IndexMap;

use crate::error::{Error, Result};
use crate::field::Field;
use crate::input::DbValue;

pub type DynField = Box<dyn Field + Send + Sync>;

pub struct Models {
    pub models: IndexMap<String, Model>,
}
impl Models {
    pub fn new() -> Self {
        Models {
            models: IndexMap::with_capacity(5),
        }
    }

    pub fn add(&mut self, model: Model) {
        self.models.insert(model.name.clone(), model);
    }

    pub fn get(&self, model: &str) -> Result<&Model> {
        match self.models.get(model) {
            Some(model) => Ok(model),
            None => Err(Error::ModelNotFound(model.to_owned())),
        }
    }
}

pub struct Model {
    pub name: String,
    pub fields: IndexMap<String, DynField>,
}

impl Model {
    pub fn new(name: impl Into<String>) -> Self {
        Model {
            name: name.into(),
            fields: IndexMap::with_capacity(16),
        }
    }

    pub fn add_field(mut self, field: DynField) -> Self {
        self.fields.insert(field.name(), field);
        self
    }

    pub fn get_field(&self, field: &str) -> Result<&DynField> {
        match self.fields.get(field) {
            Some(field) => Ok(field),
            None => Err(Error::FieldNotFound(field.to_owned())),
        }
    }

    /// From table sql
    pub fn from_sql(&self) -> String {
        self.name.clone()
    }

    pub fn create_def(&self) -> String {
        let field_defs = self
            .fields
            .values()
            .map(|f| f.db_field().create_def())
            .collect::<Vec<_>>();
        format!(
            "CREATE TABLE IF NOT EXISTS {}\n(\n  {}\n)\n",
            self.name,
            field_defs.join(",\n  ")
        )
    }
}

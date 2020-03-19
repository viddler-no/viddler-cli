use crate::db::Db;
use crate::error::Result;
use crate::input::DbValue;
/// Insert builder
use indexmap::IndexMap;

pub struct Insert {
    pub model: String,
    pub values: IndexMap<String, DbValue>,
}

impl Insert {
    pub fn new(model: impl Into<String>) -> Self {
        Insert {
            model: model.into(),
            values: IndexMap::new(),
        }
    }

    pub fn value<K, V>(&mut self, key: K, value: V) -> &mut Self
    where
        K: Into<String>,
        V: Into<DbValue>,
    {
        self.values.insert(key.into(), value.into());
        self
    }

    pub fn execute(&self, db: &Db) -> Result<()> {
        db.insert(&self.model, &self.values)?;
        Ok(())
    }
}

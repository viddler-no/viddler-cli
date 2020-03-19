use crate::error::{Error, Result};
use crate::input::DbValue;
use crate::model::{Model, Models};
use crate::query::Query;
use indexmap::IndexMap;
use rusqlite::{params, Connection, OptionalExtension, NO_PARAMS};
use std::sync::Arc;

pub struct Db {
    pub conn: Connection,
    pub models: Arc<Models>,
}
impl Db {
    pub fn conn(models: Arc<Models>) -> Result<Self> {
        let db_file = "/db/db.db3";
        let conn = Connection::open(db_file)?;
        Ok(Db { conn, models })
    }

    pub fn reset_db() -> Result<()> {
        std::fs::remove_file("/db/db.db3")?;
        Ok(())
    }

    pub fn get_model(&self, model: &str) -> Result<&Model> {
        self.models.get(model)
    }

    pub fn select_query<T, F>(&self, query: &Query, f: F) -> Result<()>
    where
        F: FnMut(&rusqlite::Row) -> Result<T>,
    {
        let sql = query.to_sql(self)?;
        let mut stmt = self.conn.prepare(&sql)?;
        // todo: Not sure what the difference between
        // query_and_then/query_map is
        // One difference is and_then takes error type parameter
        let rows = stmt.query_and_then(NO_PARAMS, f)?;
        // Mostly running the iterator, expecting the closure to
        // contain the needed code
        for row in rows {
            row?;
        }
        Ok(())
    }

    pub fn insert(&self, model: &str, values: &IndexMap<String, DbValue>) -> Result<()> {
        let model = self.get_model(model)?;
        let names = values
            .keys()
            .map(|k| k.to_owned())
            .collect::<Vec<_>>()
            .join(", ");
        let mut params = Vec::with_capacity(values.len());
        let mut placeholders = Vec::with_capacity(values.len());
        let mut i = 1;
        for (key, value) in values.iter() {
            let field = model.get_field(key)?;
            field.validate_value(value)?;
            placeholders.push(format!("?{}", i));
            params.push(value.to_rusqlite());
            i = i + 1;
        }
        let sql = format!(
            "INSERT INTO {} (\n{}\n) VALUES (\n{}\n)",
            model.name,
            names,
            placeholders.join(", ")
        );
        println!("{}", sql);
        let mut stmt = self.conn.prepare(&sql)?;
        let _row_id = stmt.insert(params)?;
        Ok(())
    }

    pub fn create_tables(&self) -> Result<()> {
        for model in self.models.models.values() {
            let create_def = model.create_def();
            self.conn.execute(&create_def, NO_PARAMS)?;
        }
        Ok(())
    }

    pub fn set_key(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "
            insert into key_values (key, value) values (
                ?1, ?2
            ) on conflict(key) do update set value = ?2
        ",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_key(&self, key: &str) -> Result<Option<String>> {
        let res = self
            .conn
            .query_row(
                "
            select value
            from key_values
            where key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(res)
    }

    pub fn add_error(
        &self,
        message: String,
        request_url: String,
        user_agent: String,
        time_created: String,
        on_client: bool,
        details: String,
    ) -> Result<()> {
        self.conn.execute(
            "
            insert into error (
                message,
                request_url,
                user_agent,
                time_created,
                on_client,
                details
            ) values (
                ?1, ?2, ?3, ?4, ?5, ?6
            )
        ",
            params![
                message,
                request_url,
                user_agent,
                time_created,
                on_client,
                details
            ],
        )?;
        Ok(())
    }
}

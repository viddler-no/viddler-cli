use crate::db::Db;
use crate::error::Result;

pub struct Query {
    pub model: String,
    pub fields: Vec<String>,
    pub order_by: Vec<OrderBy>,
    pub limit: Option<i32>
}
pub struct OrderBy {
    pub field: String,
    pub asc: bool
}
impl Query {
    pub fn new(model: impl Into<String>) -> Self {
        Query {
            model: model.into(),
            fields: Vec::new(),
            order_by: Vec::new(),
            limit: None
        }
    }

    pub fn select<T>(&mut self, add: T) -> &mut Self
    where
        T: IntoIterator,
        T::Item: Into<String>,
    {
        for s in add {
            self.fields.push(s.into());
        }
        self
    }

    pub fn order_by(&mut self, field: impl Into<String>, asc: bool) -> &mut Self {
        self.order_by.push(OrderBy {
            field: field.into(),
            asc
        });
        self
    }

    pub fn limit(&mut self, limit: i32) -> &mut Self {
        self.limit = Some(limit);
        self
    }

    pub fn to_sql(&self, conn: &Db) -> Result<String> {
        let mut b = String::with_capacity(350);
        let model = conn.get_model(&self.model)?;
        let mut select_exprs = Vec::with_capacity(self.fields.len());
        for select in &self.fields {
            let field = model.get_field(select)?;
            select_exprs.push(field.select_expr());
        }
        b.push_str("SELECT ");
        b.push_str(&select_exprs.join(", "));
        b.push_str(" FROM ");
        b.push_str(&model.from_sql());
        if self.order_by.len() > 0 {
            let mut order_statements = Vec::with_capacity(self.order_by.len());
            for order_by in &self.order_by {
                let field = model.get_field(&order_by.field)?;
                if order_by.asc {
                    order_statements.push(format!("{} ASC", field.select_expr()));
                } else {
                    order_statements.push(format!("{} DESC", field.select_expr()));
                }
            }
            b.push_str(" ORDER BY ");
            b.push_str(&order_statements.join(", "));
        }
        if let Some(limit) = self.limit {
            b.push_str(" LIMIT ");
            b.push_str(&limit.to_string());
        }
        Ok(b)
    }
}

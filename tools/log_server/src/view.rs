use crate::db::Db;
use crate::error::Result;
use crate::query::Query;

pub fn render_query(query: &Query, db: &Db) -> Result<String> {
    let mut b = String::with_capacity(2048);
    let model = db.get_model(&query.model)?;
    b.push_str("<table><tr>");
    let mut fields = Vec::new();
    for select in &query.fields {
        let field = model.get_field(select)?;
        b.push_str("<th>");
        b.push_str(&field.label());
        b.push_str("</th>");
        fields.push(field);
    }
    b.push_str("</tr>");
    db.select_query(query, |row| {
        b.push_str("<tr>");
        let mut i = 0;
        for field in &fields {
            b.push_str("<td>");
            field.render_html(&mut b, row, i)?;
            b.push_str("</td>");
            i = i + 1;
        }
        b.push_str("</tr>");
        Ok(())
    })?;
    b.push_str("</table>");
    Ok(b)
}

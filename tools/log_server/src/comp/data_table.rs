use crate::comp::{Comp, HtmlCtx};
use crate::query::Query;

use crate::view;

pub struct DataTable {
    pub query: Query,
}
impl Comp for DataTable {
    fn html(&self, mut c: HtmlCtx) {
        // This render function could maybe be closure with a flexible type?
        // (would possibly like to return Result here?)
        let html = view::render_query(&self.query, c.db).unwrap();
        c.add(&html);
    }
}

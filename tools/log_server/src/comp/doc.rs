use crate::comp::{Comp, HtmlCtx};

pub struct Doc {
    styles: Vec<String>,
}

impl Doc {
    pub fn new(styles: Vec<String>) -> Self {
        Doc { styles }
    }
}
impl Comp for Doc {
    fn html(&self, mut c: HtmlCtx) {
        /* One idea:
        c.add("html", |html| {
            html.head(|h| {
                h.if_then("styles where type=stylesheet", )
            })
        })*/
        c.add("<html><head><title>Title</title>");
        for style in &self.styles {
            c.add(&format!("<link rel=\"stylesheet\" href=\"{}\">", style));
        }
        c.add("</head><body>");
        c.children();
        c.add("</body></html>");
    }
}

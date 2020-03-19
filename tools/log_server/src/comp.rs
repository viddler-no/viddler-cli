mod data_table;
mod doc;

pub use data_table::DataTable;
pub use doc::Doc;

use crate::db::Db;
use crate::error::Result;

pub trait Comp {
    fn html(&self, c: HtmlCtx);
}

/// Some common stuff containing also a dyn Comp where
/// most of the component specific stuff is
pub struct CompBox {
    pub comp: Box<dyn Comp>,
    pub children: Vec<CompBox>,
}

impl CompBox {
    pub fn new(comp: Box<dyn Comp>, children: Vec<CompBox>) -> Self {
        CompBox { comp, children }
    }
    pub fn comp(comp: Box<dyn Comp>) -> Self {
        CompBox {
            comp,
            children: Vec::new(),
        }
    }
    pub fn html(&self, c: &mut HtmlCtx) {
        self.comp.html(HtmlCtx {
            buffer: c.buffer,
            db: c.db,
            children: &self.children,
        });
    }
    pub fn do_html(comp: &CompBox, db: &Db) -> Result<String> {
        let mut buffer = String::with_capacity(2048);
        // An empty vec of children for root
        comp.html(&mut HtmlCtx {
            buffer: &mut buffer,
            db,
            children: &Vec::new(),
        });
        Ok(buffer)
    }
}

pub struct HtmlCtx<'b, 'd, 'c> {
    pub buffer: &'b mut String,
    pub db: &'d Db,
    pub children: &'c Vec<CompBox>,
}
impl<'b, 'd, 'c> HtmlCtx<'b, 'd, 'c> {
    pub fn add(&mut self, string: &str) {
        self.buffer.push_str(string);
    }
    pub fn children(&mut self) {
        for child in self.children {
            child.html(self);
        }
    }
}

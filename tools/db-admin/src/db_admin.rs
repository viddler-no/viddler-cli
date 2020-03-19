use actix_web::{
    web::{self, HttpRequest, HttpResponse},
    Error, Result, ResponseError
};
use crate::AppData;
use mysql_utils::{Db, MyLibError};
use serde::{Serialize, Deserialize};

#[derive(Serialize)]
pub struct DbError {
    msg: String
}
impl DbError {
    pub fn msg<M: Into<String>>(msg: M) -> Self {
        DbError {
            msg: msg.into()
        }
    }
    pub fn e(e: MyLibError) -> Self {
        DbError {
            msg: format!("{:?}", e)
        }
    }
}


// Often we want to handle or show client-side
/// Converts mysql_util error
pub fn my_lib_wrap(e: MyLibError) -> Error {
    Error::from(MyLibErrorWrapper {
        e
    })
}
pub struct MyLibErrorWrapper {
    pub e: MyLibError
}
impl ResponseError for MyLibErrorWrapper {}
impl std::fmt::Debug for MyLibErrorWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MyLibError: {:?}", self.e)
    }
}
impl std::fmt::Display for MyLibErrorWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MyLibError: {:?}", self.e)
    }
}

#[derive(Deserialize)]
pub struct QueryInput {
    query: String
}
pub fn query(data: web::Data<AppData>, params: web::Json<QueryInput>,  _req: HttpRequest) -> Result<HttpResponse> {
    let mut db = match Db::new(&data.host, data.port, &data.db, &data.user, &data.pass) {
        Ok(db) => db,
        Err(e) => return Ok(HttpResponse::Ok().json(DbError::e(e)))
    };
    let query_res = match Db::query(&mut db.conn, &params.query) {
        Ok(query_res) => query_res,
        Err(e) => return Ok(HttpResponse::Ok().json(DbError::e(e)))
    };
    let display_result = match Db::display_result(query_res) {
        Ok(display_result) => display_result,
        Err(e) => return Ok(HttpResponse::Ok().json(DbError::e(e)))
    };
    Ok(HttpResponse::Ok().json(display_result))
}

#[derive(Serialize)]
struct Structure<'a> {
    tablenames: &'a Vec<String>,
    table_defs: &'a mysql_utils::TableDefMap,
}
pub fn structure(data: web::Data<AppData>, _req: HttpRequest) -> Result<HttpResponse> {
    let mut db = match Db::new(&data.host, data.port, &data.db, &data.user, &data.pass) {
        Ok(db) => db,
        Err(e) => return Ok(HttpResponse::Ok().json(DbError::e(e)))
    };
    match db.init_table_defs() {
        Ok(_) => (),
        Err(e) => return Ok(HttpResponse::Ok().json(DbError::e(e)))
    }
    let table_defs = db.table_defs().map_err(my_lib_wrap)?;
    let tablenames = db.tablenames().map_err(my_lib_wrap)?;
    Ok(HttpResponse::Ok().json(Structure {
        tablenames,
        table_defs
    }))
}
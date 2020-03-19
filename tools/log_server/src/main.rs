#[macro_use]
extern crate actix_web;

mod comp;
mod db;
mod error;
mod field;
mod input;
mod insert;
mod model;
mod query;
mod utils;
mod view;

use comp::{Comp, CompBox, DataTable, Doc};
use db::Db;
use field::{BoolField, DateTimeField, IdField, TextField};
use indexmap::IndexMap;
use insert::Insert;
use model::{Model, Models};
use query::Query;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utils::{DateTimeVal, html_resp, json_resp};
use std::path::PathBuf;

use actix_web::{
    http::StatusCode,
    middleware,
    web::{self, Data},
    App, Error, HttpResponse, HttpServer, ResponseError,
};

use actix_files as fs;

impl ResponseError for error::Error {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::InternalServerError().body(format!("{}", self))
    }
}

fn define_models() -> Models {
    let mut models = Models::new();
    models.add(
        Model::new("key_values")
            .add_field(TextField::primary("key"))
            .add_field(TextField::text("value")),
    );

    models.add(
        Model::new("error")
            .add_field(IdField::id())
            .add_field(TextField::text("request_url"))
            .add_field(TextField::text("ip"))
            .add_field(TextField::text("user_agent"))
            .add_field(TextField::text("referrer"))
            .add_field(TextField::text("message"))
            .add_field(DateTimeField::date("time"))
            .add_field(BoolField::boolean("on_client"))
            .add_field(TextField::text("file"))
            .add_field(TextField::text("line"))
            .add_field(TextField::text("col"))
            .add_field(TextField::text("details")),
    );

    models.add(
        Model::new("visit")
            .add_field(IdField::id())
            .add_field(TextField::text("request_url"))
            .add_field(TextField::text("ip"))
            .add_field(TextField::text("user_agent"))
            .add_field(TextField::text("referrer"))
            .add_field(DateTimeField::date("time"))
            .add_field(TextField::text("details")),
    );
    models
}

#[get("/visits")]
async fn visits(
    data: Data<AppData>,
) -> Result<HttpResponse, Error> {
    let db = Db::conn(data.models.clone())?;
    let mut query = Query::new("visit");
    query.select(vec![
        "time",
        "request_url",
        "ip",
        "user_agent",
        "referrer",
        "details",
    ]);
    query.order_by("id", false);
    query.limit(500);
    let comp = CompBox::new(
        Box::new(Doc::new(vec!["/assets/style.css".into()])),
        vec![CompBox::new(Box::new(DataTable { query }), Vec::new())],
    );
    let html = CompBox::do_html(&comp, &db)?;
    Ok(html_resp(html))
}

#[get("/errors")]
async fn errors(
    data: Data<AppData>,
) -> Result<HttpResponse, Error> {
    let db = Db::conn(data.models.clone())?;
    let mut query = Query::new("error");
    query.select(vec![
        "time",
        "request_url",
        "ip",
        "user_agent",
        "referrer",
        "message",
        "on_client",
        "file",
        "line",
        "col",
        "details",
    ]);
    query.order_by("id", false);
    query.limit(500);
    let comp = CompBox::new(
        Box::new(Doc::new(vec!["/assets/style.css".into()])),
        vec![CompBox::new(Box::new(DataTable { query }), Vec::new())],
    );
    let html = CompBox::do_html(&comp, &db)?;
    Ok(html_resp(html))
}

#[derive(Deserialize)]
pub struct InsertJson {
    model: String,
    inputs: IndexMap<String, serde_json::Value>,
}

#[derive(Serialize)]
pub struct InsertResponse {
    success: bool,
}
impl InsertResponse {
    pub fn success() -> Self {
        InsertResponse { success: true }
    }
}

#[post("/insert")]
async fn insert_req(
    data: Data<AppData>,
    input: web::Json<InsertJson>,
) -> Result<HttpResponse, Error> {
    let model = data.models.get(&input.model)?;
    let mut insert = Insert::new(&input.model);
    for (key, value) in &input.inputs {
        let field = model.get_field(key)?;
        insert.value(key, field.json_to_input(value)?);
    }
    let db = Db::conn(data.models.clone())?;
    insert.execute(&db)?;
    Ok(json_resp(InsertResponse::success()))
}

fn init_db(models: Arc<Models>) -> error::Result<()> {
    let db = Db::conn(models)?;
    db.create_tables()?;
    /*
    let mut q = Insert::new("visit");
    q.value("request_url", "/")
        .value("ip", "127.0.0.1")
        .value("user_agent", "Mozilla")
        .value("referrer", "http://google.com")
        .value(
            "time",
            DateTimeVal::try_from("2019-12-31 12:00:12")?,
        )
        .value("details", "Details");

    q.execute(&db)?;*/
    Ok(())
}

#[get("/assets/style.css")]
async fn style(data: Data<AppData>) -> Result<fs::NamedFile, Error> {
    let assets = std::path::Path::new(&data.assets);
    Ok(fs::NamedFile::open(assets.join("style.css"))?)
}

/// This is a big to public
#[get("/reset-db")]
async fn reset_db(data: Data<AppData>) -> Result<HttpResponse, Error> {
    Db::reset_db()?;
    init_db(data.models.clone())?;
    Ok(html_resp("Reset db".into()))
}

pub struct AppData {
    models: Arc<Models>,
    assets: PathBuf
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();

    let models = Arc::new(define_models());

    init_db(models.clone()).unwrap();

    // Assets folder
    let assets = PathBuf::from("/var/lib/log_server/assets");

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(AppData {
                models: models.clone(),
                assets: assets.clone()
            }))
            // Always register last
            .wrap(middleware::Logger::default())
            .service(style)
            .service(visits)
            .service(errors)
            .service(insert_req)
            .service(reset_db)
    })
    .bind("0.0.0.0:7006")?
    .run()
    .await
}

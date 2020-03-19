use actix_web::{HttpRequest, HttpResponse, Error, web, http::StatusCode, web::BytesMut};
use crate::{Mode, AppData};
use futures::{Future, future::{self, Either}, stream::Stream};
use awc::Client;
use crate::util::header_string;
use serde::Serialize;
use indexmap::IndexMap;
use actix::prelude::*;

pub type Values = IndexMap<String, serde_json::Value>;

#[derive(Serialize)]
pub struct Insert {
    pub model: String,
    pub inputs: Values,
}

// This is handler from js side
pub fn log_visit(
    data: web::Data<AppData>,
    req: HttpRequest,
    mut values: web::Json<Values>,
    dev_mode: Mode
) -> impl Future<Item = HttpResponse, Error = Error> {
    let mut values = values.0;
    add_common_fields(&req, &mut values);
    json_req_res("insert", &Insert {
        model: "visit".into(),
        inputs: values
    })
}

/// Small helper to log a visit when handled by server
pub fn log_visit_server(
    url_path: &str,
    req: &HttpRequest,
    log_actor: &Addr<LogActor>
) {
    let mut values: crate::log_server::Values = indexmap::IndexMap::new();
    values.insert("request_url".into(), format!("/{}", url_path).into());
    values.insert("details".into(), "".into());
    add_common_fields(req, &mut values);
    // Send and forget
    log_actor.do_send(crate::log_server::LogEntry {
        model: "visit".into(),
        values
    });
}

pub fn log_error(
    data: web::Data<AppData>,
    req: HttpRequest,
    mut values: web::Json<Values>,
    dev_mode: Mode
) -> impl Future<Item = HttpResponse, Error = Error> {
    let mut values = values.0;
    add_common_fields(&req, &mut values);
    json_req_res("insert", &Insert {
        model: "error".into(),
        inputs: values
    })
}

fn add_common_fields(req: &HttpRequest, values: &mut Values) {
    // Collect ip, user agent and referrer,
    let ip = match req.connection_info().remote() {
        Some(ip) => ip.to_string(),
        None => String::from("")
    };
    let headers = req.headers();
    let user_agent = header_string(headers, "User-Agent");
    let referrer = header_string(headers, "Referer");
    // also collecting time to ease/ensure consistency
    let time = chrono::Utc::now().format("%Y-%m-%d  %H:%M:%S").to_string();

    values.insert("ip".into(), ip.into());
    values.insert("user_agent".into(), user_agent.into());
    values.insert("referrer".into(), referrer.into());
    values.insert("time".into(), time.into());
}

/// Sends a json request to log_server
fn json_req<'a, J>(path: &str, json: &'a J) -> impl Future<Item = (StatusCode, BytesMut), Error = Error>
where J: serde::Serialize {
    let json = match serde_json::to_string(json) {
        Ok(json) => json,
        Err(e) => return Either::A(future::err(e.into()))
    };
    let client = Client::default();
    Either::B(client.post(&format!("http://log-server:7006/{}", path))
        .header("Content-Type", "application/json")
        .send_body(json)
        .map_err(|e| e.into())
        .and_then(|resp| {
            let status = resp.status();
            resp.from_err()
                .fold(web::BytesMut::new(), |mut acc, chunk| {
                    acc.extend_from_slice(&chunk);
                    Ok::<_, Error>(acc)
                })
                .and_then(move |body| {
                    Ok((status, body))
                })
        }))
}
/// Sends a json request to log_server, and returns the response as a json response
fn json_req_res<'a, J>(path: &str, json: &'a J) -> impl Future<Item = HttpResponse, Error = Error>
where J: serde::Serialize {
    json_req(path, json)
        .and_then(|(status, body)| {
            let mut client_resp = HttpResponse::build(status);
            client_resp.header("Content-Type", "application/json");
            Ok(client_resp.body(body))
        })
}

// Actor to log out of request time
pub struct LogActor;

pub struct LogEntry {
    pub model: String,
    pub values: Values
}
impl Message for LogEntry {
    type Result = Result<bool, String>;
}

impl Actor for LogActor {
    type Context = Context<LogActor>;
}

impl Handler<LogEntry> for LogActor {
    type Result = Box<dyn Future<Item = bool, Error = String>>;

    fn handle(&mut self, msg: LogEntry, ctx: &mut Context<Self>) -> Box<dyn Future<Item = bool, Error = String>> {
        Box::new(json_req("insert", &Insert {
            model: msg.model,
            inputs: msg.values
        })
        .map_err(|e| format!("Request failed: {:?}", e))
        .and_then(|(status, body)| {
            if status == StatusCode::OK {
                Ok(true)
            } else {
                println!("LogEntry failed: {}", String::from_utf8_lossy(&body.freeze().to_vec()));
                Ok(false)
            }
        }))
    }
}
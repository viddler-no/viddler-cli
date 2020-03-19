mod db_admin;

use actix_web::{middleware, http::uri::Uri, web, App, HttpRequest, HttpServer};
use futures::future::Either;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

//#[derive(Clone)]
pub struct AppData {
    host: String,
    port: u16,
    db: String,
    user: String,
    pass: String,
    dev_mode: bool,
}

use clap::{self, Arg};

// todo: consider backtrace crate
fn main() {
    let matches = clap::App::new("db-admin")
        .version("0.1")
        .author("Gudmund")
        .about("Db admin")
        .arg(
            Arg::with_name("dev-mode")
                .short("d")
                .long("dev-mode")
                .value_name("DEV_MODE")
                .env("DEV_MODE")
                .help("Dev mode with no proxy caching")
                .required(false)
                .takes_value(true),
        )
        .get_matches();

    // Dev mode
    let dev_mode: bool = match matches.value_of("dev-mode") {
        Some(dev_mode) => match dev_mode {
            "0" | "false" | "no" => false,
            _ => true,
        },
        None => false,
    };
    let sys = actix_rt::System::new("db-admin");
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();
    // Setting up services
    let server = HttpServer::new(move || {
        let app = App::new()
            .data(AppData {
                host: "127.0.0.1".into(),
                port: 3307,
                db: "wordpress".into(),
                user: "wordpress".into(),
                pass: "wordpress".into(),
                dev_mode,
            })
            .wrap(middleware::Logger::default())
            .service(web::resource("/query").to(db_admin::query))
            .service(web::resource("/structure").to(db_admin::structure))
            // first url path, then file path
            .service(actix_files::Files::new("/", "./frontend/public").index_file("index.html"));
        app
    });
    let server = server.bind("127.0.0.1:4242");
    match server {
        Ok(server) => {
            server.start();
            println!("Listening on 127.0.0.1:4242");
            match sys.run() {
                Ok(()) => (),
                Err(err) => {
                    println!("Failed running system: {:?}", err);
                    std::process::exit(1);
                }
            }
        }
        Err(err) => {
            println!("Failed binding server: {:?}", err);
            std::process::exit(1);
        }
    }
}


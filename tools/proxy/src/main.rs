#[macro_use]
extern crate tantivy;

mod chunked_file;
mod proxy;
mod util;
mod search;
mod letsencrypt;
mod redir_middleware;
mod log_server;

use proxy::*;

use actix_cors::Cors;
use actix_web::{middleware, http::uri::Uri, web, App, HttpRequest, HttpServer};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use util::uri_to_string;

use redir_middleware::RedirMiddleware;

// Tentative setup
#[derive(Clone, Debug)]
pub struct StaticResolved {
    file: PathBuf,
    if_webp: Option<PathBuf>,
}

//#[derive(Clone)]
pub struct AppData {
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    /// Cached urls's dependent on keyed id's
    cache_dep_id: Arc<RwLock<HashMap<u32, HashSet<String>>>>,
    /// Cached urls's dependent added/deleted pods
    cache_dep_pod: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    /// Cached urls's dependent changes in pods
    /// This is used when a list has conditions, and it would be better to
    /// be specific about the conditions, could get a list of updated fields
    /// from wp, or based on fields here, send back request about whether
    /// those fields have changed
    /// todo: This is unimplemented, should also handle related pod
    cache_dep_pod_change: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    cache_timeouts: Arc<RwLock<BTreeMap<i64, HashSet<String>>>>,
    path_configs: Arc<RwLock<HashMap<PathConfigKey, PathConfig>>>,
    static_resolved: Arc<RwLock<HashMap<String, Option<StaticResolved>>>>,
    index_data: Option<search::AllIndexData>,
    cache_dir: String,
    img_exp_minute_interval: u32,
    page_exp_minute_interval: u32,
    dev_mode: bool,
    /// Proxied without scheme
    proxied: String,
    // url_path used like <root>/<not_found_page>
    not_found_page: String,
    // url_path used like <root>/<error_page>
    error_page: String,
    log_actor: actix::Addr<log_server::LogActor>
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PathConfigKey(pub String);

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Alias {
    from: String,
    to: String
}
impl Alias {
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Alias {
            from: from.into(),
            to: to.into()
        }
    }
    pub fn has_path(set: &HashSet<Alias>, url_path: &str) -> bool {
        for alias in set {
            if url_path == alias.from {
                return true;
            }
        }
        false
    }
    pub fn process(set: &HashSet<Alias>, url_path: &str) -> String {
        for alias in set {
            if url_path == alias.from {
                return alias.to.clone();
            }
        }
        url_path.to_owned()
    }
}

#[derive(Clone)]
struct PathConfig {
    request_base: String,
    key: PathConfigKey,
    url_path_prefix: String,
    replacements: Vec<(String, String)>,
    aliases: HashSet<Alias>,
    forward: HashSet<String>,
    fold_redirects: bool,
    static_paths: Option<Vec<(String, String)>>,
    //cache_config: PathCacheConfig
}
#[derive(Clone)]
enum PathCache {
    IntervalMinutes(u32)
}
impl PathCache {
    pub fn minute_interval(minutes: u32) -> Self {
        PathCache::IntervalMinutes(minutes)
    }
    pub fn days_interval(days: u32) -> Self {
        PathCache::IntervalMinutes(60*24*days)
    }
}
#[derive(Clone)]
struct PathCacheConfig {
    img: PathCache,
    page: PathCache,
    css: PathCache,
    font: PathCache,
    other: PathCache
}

use clap::{self, Arg};

pub struct Mode {
    dev_mode: bool,
    wp_admin: bool
}
impl Mode {
    pub fn dev_or_admin(&self) -> bool {
        self.dev_mode || self.wp_admin
    }
}

fn is_dev_mode(req: &HttpRequest, data: &web::Data<AppData>) -> Mode {
    let wp_admin = match util::header_opt(req.headers(), "Cookie") {
        Some(cookie_str) => {
            // If logged in, assume dev mode (todo: This doesn't seem very secure, could verify with db)
            cookie_str.contains("wordpress_logged_in")
        }
        None => false
    };
    Mode {
        dev_mode: data.dev_mode,
        wp_admin
    }
}

// todo: consider backtrace crate
fn main() {
    let matches = clap::App::new("Proxy server")
        .version("0.1")
        .author("Gudmund")
        .about("Proxies wordpress and other things to some other url with caching")
        .arg(
            Arg::with_name("wp")
                .short("w")
                .long("wordpress")
                .value_name("WORDPRESS")
                .env("WORDPRESS")
                .help("Wordpress url")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("external")
                .short("e")
                .long("external")
                .value_name("EXTERNAL")
                .env("EXTERNAL")
                .help("External address used to connect to site")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("uploads-path")
                .short("u")
                .long("uploads-path")
                .value_name("UPLOADS_PATH")
                .env("UPLOADS_PATH")
                .help("Path to wordpress' upload directory")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cache-dir")
                .short("c")
                .long("cache-dir")
                .value_name("CACHE_DIR")
                .env("CACHE_DIR")
                .help("Where to place cache files")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ssl")
                .short("s")
                .long("ssl")
                .value_name("SSL")
                .env("SSL")
                .help("Whether to serve over https")
                .required(false)
                .takes_value(true),
        )
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

    // Wp url
    let wp_uri: Uri = match matches.value_of("wp") {
        Some(wp) => match wp.parse::<Uri>() {
            Ok(uri) => uri,
            Err(err) => {
                println!("Could not parse wp uri: {}", err);
                std::process::exit(2);
            }
        },
        None => {
            println!("Url of wordpress is required");
            std::process::exit(2);
        }
    };
    let (proxied, proxied_no_scheme) = match (
        uri_to_string(wp_uri.clone(), true, true),
        uri_to_string(wp_uri, false, true),
    ) {
        (Ok(uri), Ok(no_scheme)) => (uri, no_scheme),
        _ => {
            println!("Could not parse wp uri, scheme://host[:port]");
            std::process::exit(2);
        }
    };
    // External uri
    let external: Uri = match matches.value_of("external") {
        Some(external) => match external.parse::<Uri>() {
            Ok(uri) => uri,
            Err(err) => {
                eprintln!("Could not parse external uri: {}", err);
                std::process::exit(2);
            }
        },
        None => {
            eprintln!("External uri required");
            std::process::exit(2);
        },
    };
    // Cache dir
    let cache_dir: String = match matches.value_of("cache-dir") {
        Some(cache_dir) => cache_dir.to_owned(),
        None => {
            println!("Cache dir is required");
            std::process::exit(2);
        }
    };
    // Uploads path
    let uploads_path: String = match matches.value_of("uploads-path") {
        Some(uploads_path) => uploads_path.to_owned(),
        None => {
            println!("Wordpress upload path is required");
            std::process::exit(2);
        }
    };
    // Ssl
    // todo: This is overwritten, and probably not needed
    let ssl: bool = match matches.value_of("ssl") {
        Some(ssl) => match ssl {
            "0" | "false" | "no" => false,
            _ => true,
        },
        None => false,
    };
    // Dev mode
    let dev_mode: bool = match matches.value_of("dev-mode") {
        Some(dev_mode) => match dev_mode {
            "0" | "false" | "no" => false,
            _ => true,
        },
        None => false,
    };
    // Making encrypter if we are given https domain,
    // and checking whether there are certificates with time remaining
    let domain_info = util::uri_to_https_domain(&external);
    let redir_www = match &domain_info {
        Some((_, true)) => true,
        _ => false
    };
    let (encrypter, certificate) = match domain_info {
        Some((https_domain, _)) => {
            let alts = vec![
                format!("www.{}", https_domain)
            ];
            let encrypter = letsencrypt::LetsEncrypt::new(https_domain, alts);
            let certificate = match encrypter.certificate() {
                Ok(Some(certificate)) => {
                    if certificate.valid_days_left() > 0 {
                        Some(certificate)
                    } else {
                        None
                    }
                }
                _ => None
            };
            (Some(encrypter), certificate)
        },
        None => (None, None)
    };
    let external_uri = match uri_to_string(external, false, true) {
        Ok(uri) => {
            if certificate.is_some() {
                format!("https://{}", uri)
            } else {
                format!("http://{}", uri)
            }
        },
        Err(_) => {
            println!("Could not parse external uri, scheme://host[:port]");
            std::process::exit(2);
        }
    };

    let cache: Arc<RwLock<HashMap<String, CacheEntry>>> = Arc::new(RwLock::new(HashMap::new()));
    let cache_dep_id: Arc<RwLock<HashMap<u32, HashSet<String>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let cache_dep_pod: Arc<RwLock<HashMap<String, HashSet<String>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let cache_dep_pod_change: Arc<RwLock<HashMap<String, HashSet<String>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let cache_timeouts: Arc<RwLock<BTreeMap<i64, HashSet<String>>>> =
        Arc::new(RwLock::new(BTreeMap::new()));
    // Path configs, keyed by request_base
    let path_configs: Arc<RwLock<HashMap<PathConfigKey, PathConfig>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let static_resolved: Arc<RwLock<HashMap<String, Option<StaticResolved>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    // Path config keys
    // todo: Could DRY this up a little, there is also
    // stuff in the services
    let wp_path_key = PathConfigKey("".into());
    let google_font_path_key = PathConfigKey("googlefont".into());
    let google_static_path_key = PathConfigKey("googlestatic".into());
    let wp_admin_key = PathConfigKey("wp-admin".into());
    let wp_json_key = PathConfigKey("wp-json".into());
    let wp_json_cache_key = PathConfigKey("wp-json-cache".into());
    {
        let mut write_path_configs = path_configs.write().unwrap();
        // Root (wp client)
        use std::iter::FromIterator;
        write_path_configs.insert(
            wp_path_key.clone(),
            PathConfig {
                request_base: proxied.clone(),
                url_path_prefix: String::from(""),
                key: wp_path_key,
                replacements: vec![
                    (proxied.clone(), external_uri.clone()),
                    (
                        String::from("https://fonts.googleapis.com"),
                        external_uri.clone() + "/googlefont",
                    ),
                ],
                aliases: HashSet::from_iter(
                    vec![
                        Alias::new("sitemap.xml", "sitemap/"),
                        Alias::new("favicon.ico", "wp-content/themes/brygga-theme/img/favicons/favicon.ico"),
                        Alias::new("manifest.json", "wp-content/themes/brygga-theme/manifest.json"),
                        Alias::new("sw.js", "wp-content/themes/brygga-theme/sw.php"),
                    ]
                ),
                forward: HashSet::from_iter(
                    vec![
                        "wp-login.php".into(),
                        "wp-admin".into(),
                        "sitemap/".into()
                    ].into_iter(),
                ),
                fold_redirects: false,
                static_paths: Some(vec![("wp-content/uploads".into(), uploads_path)]),
                //static_paths: None
            },
        );
        // Google fonts
        write_path_configs.insert(
            google_font_path_key.clone(),
            PathConfig {
                request_base: String::from("https://fonts.googleapis.com"),
                url_path_prefix: String::from("googlefont"),
                key: google_font_path_key,
                replacements: vec![
                    (
                        String::from("https://fonts.googleapis.com"),
                        external_uri.clone() + "/googlefont",
                    ),
                    (
                        String::from("https://fonts.gstatic.com"),
                        external_uri.clone() + "/googlestatic",
                    ),
                ],
                fold_redirects: true,
                forward: HashSet::new(),
                aliases: HashSet::new(),
                static_paths: None,
            },
        );
        // Google static
        write_path_configs.insert(
            google_static_path_key.clone(),
            PathConfig {
                request_base: String::from("https://fonts.gstatic.com"),
                url_path_prefix: String::from("googlestatic"),
                key: google_static_path_key,
                replacements: vec![],
                forward: HashSet::new(),
                aliases: HashSet::new(),
                fold_redirects: true,
                static_paths: None,
            },
        );
        // Wp-admin
        write_path_configs.insert(
            wp_admin_key.clone(),
            PathConfig {
                request_base: proxied.clone() + "/wp-admin",
                url_path_prefix: String::from("wp-admin"),
                key: wp_admin_key,
                replacements: vec![(proxied.clone(), external_uri.clone())],
                forward: HashSet::new(),
                aliases: HashSet::new(),
                fold_redirects: false,
                static_paths: None,
            },
        );
        // Wp-json
        write_path_configs.insert(
            wp_json_key.clone(),
            PathConfig {
                request_base: proxied.clone() + "/wp-json",
                url_path_prefix: String::from("wp-json"),
                key: wp_json_key,
                replacements: vec![(proxied.clone(), external_uri.clone())],
                forward: HashSet::new(),
                aliases: HashSet::new(),
                fold_redirects: false,
                static_paths: None,
            },
        );
        // Wp-json cached
        write_path_configs.insert(
            wp_json_cache_key.clone(),
            PathConfig {
                request_base: proxied.clone() + "/wp-json",
                url_path_prefix: String::from("wp-json-cache"),
                key: wp_json_cache_key,
                replacements: vec![(proxied.clone(), external_uri.clone())],
                forward: HashSet::new(),
                aliases: HashSet::new(),
                fold_redirects: false,
                static_paths: None,
            },
        );
    }
    let mut sys = actix_rt::System::new("proxy");
    let index_data = match search::initial_index_data() {
        Ok(index_data) => Some(index_data),
        Err(e) => {
            // I don't think we want to fail in this case,
            // though should report error clearly
            eprintln!("Could not get initial index data: {:?}", e);
            None
        }
    };
    // todo: Retry until all-menus

    let ssl_builder = match certificate {
        Some(certificate) => {
            match &encrypter {
                Some(encrypter) => {
                    match encrypter.ssl_builder(certificate) {
                        Ok(builder) => {
                            Some(builder)
                        }
                        Err(e) => {
                            eprintln!("Failed to make ssl_builder: {}", e);
                            std::process::exit(2);
                        }
                    }
                }
                None => {
                    eprintln!("Has ssl without encrypter");
                    std::process::exit(2);
                }
            }
        }
        None => None
    };
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();
    let init_index_data = index_data.clone();
    let has_ssl = ssl_builder.is_some();
    // Start LogActor
    let log_actor = (log_server::LogActor).start();
    // Setting up services
    let server = HttpServer::new(move || {
        let proxied = proxied_no_scheme.clone();
        let app = App::new()
            .data(AppData {
                cache: cache.clone(),
                cache_dep_id: cache_dep_id.clone(),
                cache_dep_pod: cache_dep_pod.clone(),
                cache_dep_pod_change: cache_dep_pod_change.clone(),
                cache_timeouts: cache_timeouts.clone(),
                path_configs: path_configs.clone(),
                static_resolved: static_resolved.clone(),
                index_data: index_data.clone(),
                cache_dir: cache_dir.clone(),
                img_exp_minute_interval: 60*24*7,
                page_exp_minute_interval: 10,
                dev_mode,
                proxied,
                not_found_page: "fant-ikke-siden".into(),
                error_page: "feilmelding".into(),
                log_actor: log_actor.clone()
            })
            .wrap(middleware::Compress::default())
            .wrap(Cors::new())
            .wrap(middleware::Condition::new(has_ssl, RedirMiddleware::new(redir_www)))
            .wrap(middleware::Logger::default())
            // letsencrypt http challenge
            .service(web::resource("/.well-known/acme-challenge/{token}").to(letsencrypt::nonce_request))
            // Todo: Move these behind a dedicated path probably
            .service(web::resource("/--id-changed/{pod}/{id}").to_async(id_changed)) // todo: post
            .service(web::resource("/--pod-added/{pod}").to_async(pod_added))
            .service(web::resource("/--cache-status").to(cache_status))
            .service(web::resource("/--clear-cache").to(clear_cache))
            .service(web::resource("/--index-menus").to_async(search::index_menus))
            .service(web::resource("/search").to(search::search_handler))
            .service(web::resource("/googlefont/{url_path:.*}").to_async(
                |req: HttpRequest, data: web::Data<AppData>, payload: web::Payload| {
                    let is_dev_mode = is_dev_mode(&req, &data);
                    do_request_std(data, req, payload, PathConfigKey("googlefont".into()), is_dev_mode)
                },
            ))
            .service(web::resource("/googlestatic/{url_path:.*}").to_async(
                |req: HttpRequest, data: web::Data<AppData>, payload: web::Payload| {
                    let is_dev_mode = is_dev_mode(&req, &data);
                    do_request_std(data, req, payload, PathConfigKey("googlestatic".into()), is_dev_mode)
                },
            ))
            .service(web::resource("/wp-admin/{url_path:.*}").to_async(
                |req: HttpRequest, data: web::Data<AppData>, payload: web::Payload| {
                    let is_dev_mode = is_dev_mode(&req, &data);
                    do_request_forward(data, req, payload, PathConfigKey("wp-admin".into()), is_dev_mode)
                },
            ))
            .service(web::resource("/wp-json/{url_path:.*}").to_async(
                |req: HttpRequest, data: web::Data<AppData>, payload: web::Payload| {
                    let is_dev_mode = is_dev_mode(&req, &data);
                    do_request_forward(data, req, payload, PathConfigKey("wp-json".into()), is_dev_mode)
                },
            ))
            .service(web::resource("/wp-json-cache/{url_path:.*}").to_async(
                |req: HttpRequest, data: web::Data<AppData>, payload: web::Payload| {
                    let is_dev_mode = is_dev_mode(&req, &data);
                    do_request_std(data, req, payload, PathConfigKey("wp-json-cache".into()), is_dev_mode)
                },
            ))
            .service(web::resource("/servering_og_uteliv/{url_path:.*}").to(
                || {
                    actix_web::HttpResponse::MovedPermanently()
                        .header(actix_web::http::header::LOCATION, "/servering-og-uteliv")
                        .finish()
                },
            ))
            .service(web::resource("/--log-visit").route(web::post().to_async(
                |req: HttpRequest, data: web::Data<AppData>, values: web::Json<indexmap::IndexMap<String, serde_json::Value>>| {
                    let is_dev_mode = is_dev_mode(&req, &data);
                    log_server::log_visit(data, req, values, is_dev_mode)
                }
            )))
            .service(web::resource("/--log-error").route(web::post().to_async(
                |req: HttpRequest, data: web::Data<AppData>, values: web::Json<indexmap::IndexMap<String, serde_json::Value>>| {
                    let is_dev_mode = is_dev_mode(&req, &data);
                    log_server::log_error(data, req, values, is_dev_mode)
                }
            )))
            .service(web::resource("/{url_path:.*}").to_async(
                move |req: HttpRequest, data: web::Data<AppData>, payload: web::Payload| {
                    let is_dev_mode = is_dev_mode(&req, &data);
                    // Rather than exception for customizer, doing forwards when logged in
                    if is_dev_mode.wp_admin {
                        return Either::A(do_request_forward(
                            data,
                            req,
                            payload,
                            PathConfigKey("".into()),
                            is_dev_mode
                        ));
                    }
                    // Quick exception here for a page in customizer
                    /*
                    if let Some(query) = req.uri().query() {
                        println!("Query {}", &query);
                        if query.starts_with("customize_changeset_uuid") {
                            clear_cache_data(&data);
                            return Either::A(do_request_forward(
                                data,
                                req,
                                payload,
                                PathConfigKey("".into()),
                                Some(replace_host.clone()),
                            ));
                        }
                    }*/
                    Either::B(do_request_std(data, req, payload, PathConfigKey("".into()), is_dev_mode))
                },
            ));
        app
    });
    // Do initial search index
    /*match sys.block_on(search::index_menus_internal(init_index_data)) {
        Ok(_) => {
            println!("Did create search index");
        },
        Err(e) => {
            println!("Failed search indexing: {:?}", e);
        }
    };*/
    let server = if let Some(ssl_builder) = ssl_builder {
        println!("Binding ssl");
        match server.bind_ssl("0.0.0.0:443", ssl_builder) {
            Ok(server) => server,
            Err(_) => {
                eprintln!("Could not bind ssl, is 443 port in use?");
                std::process::exit(2);
            }
        }
    } else {
        server
    };
    // Attempt to bind regular
    let server = match server.bind("0.0.0.0:80") {
        Ok(server) => server,
        Err(_) => {
            eprintln!("Could not bind server, is the configured port in use?");
            std::process::exit(2);
        }
    };
    use actix::Actor;
    // Run encrypter actor that checks for certificate at startup,
    // and attempts to build if missing/non-valid also wrt days left
    // Will run at a specified interval as well
    match encrypter {
        Some(encrypter) => {
            let _ = encrypter.start();
        }
        None => ()
    }
    use futures::future::*;
    // Well this seems to work, but using actor runtime in actix-web,
    // I don't understand runtimes and executors good enough
    // After getting spawn panic from tokio-current-thread as awc spawns,
    // I added lazy after reading this comment:
    // https://github.com/tokio-rs/tokio/issues/382#issuecomment-447085878
    match init_index_data {
        Some(init_index_data) => {
            actix::Arbiter::spawn(
                futures::future::lazy(|| {
                    search::index_menus_internal(init_index_data)
                        .map_err(|e| {
                            eprintln!("Index menus init error: {:?}", e);
                            ()
                        })
                })
            );
        }
        None => ()
    }
    /*
    let indexer = search::SearchIndexActor {
        index_data: init_index_data
    };*/
    server.start();
    println!("Listening on 0.0.0.0");
    match sys.run() {
        Ok(()) => (),
        Err(err) => {
            println!("Failed running system: {:?}", err);
            std::process::exit(1);
        }
    }
}

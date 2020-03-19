use crate::util::replace_urls_rev;
use crate::util::*;
use crate::{AppData, PathConfig, PathConfigKey, StaticResolved, Mode};
use actix_multipart::Multipart;
use actix_web::{
    client::{self, Client},
    http::{
        header::{self, HeaderValue},
        StatusCode,
    },
    web::{self, BytesMut},
    Error, HttpRequest, HttpResponse,
};
//use actix_http::encoding::Encoder;
use actix_web::http::header::HttpDate;
use futures::{
    future::{self, Either},
    stream::Stream,
    Future,
};
use serde::Deserialize;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::log_server::log_visit_server;

// todo: https://github.com/serbanghita/Mobile-Detect/ on proxy
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Browser_detection_using_the_user_agent
// Can we preload images more intelligently? Also serving js/css based on
// user agent would be nice

// thought: How would it be if things like wordpress could output template
// code ala tera/liquid. Could the proxy do meaningful things with it
// One case is to only expire a certain area.
// Another to split response into areas of a page automatically
// with javascript help (though preferably not to crawlers)

// Could be next gen with data loading based on keys in template
// Possibly an approach more closer to html would be nice, as
// structured access to html could also be helpful
// Streaming handling would be advantagous but possibly tricky

// todo: On the fly html/js/css optimization.
// Whitespace and comment removal. Fairly easy in html,
// In tandem with browser detection above it would be possible
// to polyfill js only when supporting user agent is not detected

/// Info from wp embedded in html response
/// about dependencies
// Possibly BTreeSet could be better for `difference` performance
#[derive(Deserialize, Debug, Clone)]
struct WpCacheInfo {
    cache_ids: HashSet<u32>,
    pod_types: HashSet<String>,
    pod_change: HashSet<String>,
    date: Option<i64>,
    preloads: Vec<PreloadLink>,
}

// todo: Struct + refactor wp side
/// (link, priority)
#[derive(Clone, Debug, Deserialize)]
pub enum PreloadLink {
    Style(String, u32),
    Script(String, u32),
    Image(String, u32),
    Font(String, u32),
}

/// Information about and cached data for
/// a cache entry
/// String points to cache file, could do others here like
/// memcache, local memory.
// Could consider other types here like html, style, image if use
#[derive(Clone)]
enum CacheEntryData {
    Text(String),
    Binary(String),
}

#[derive(Clone)]
pub struct CacheEntry {
    content_type: String,
    // For this purpose, pages are considered html responses
    // it is used to 
    is_page: bool,
    expire: Option<i64>,
    last_modified: Option<String>,
    etag: Option<String>,
    headers: Vec<(String, String)>,
    preloads: Option<String>,
    data: CacheEntryData,
    path_config: PathConfigKey,
    cache_info: Option<Box<WpCacheInfo>>,
}

/// Helper struct used during
/// request to communicate relevant
/// response data
struct ResponseData {
    content_type: String,
    last_modified: Option<String>,
    etag: Option<String>,
    headers: Vec<(String, String)>,
    is_page: bool,
    body: ResponseBodyData,
}
fn is_page(headers: &header::HeaderMap) -> bool {
    match headers.get("x-is-page") {
        Some(header_val) => header_val == "1",
        None => false
    }
}
impl ResponseData {
    // Return response data from non-200 status code, later we will fill
    // response with special pages for 404 and error
    pub fn from_non_200_status_code(
        status_code: StatusCode,
        body: web::BytesMut,
        replacements: Vec<(String, String)>,
        headers: &header::HeaderMap
    ) -> Result<ResponseData, Error> {
        let is_page = is_page(headers);
        match ResponseBodyData::from_non_200_status_code(status_code, body, replacements, headers) {
            body @ ResponseBodyData::Redirect(_, _) => {
                Ok(ResponseData {
                    content_type: header_string(headers, "content-type"),
                    is_page,
                    last_modified: None,
                    etag: None,
                    headers: Vec::new(),
                    body
                })
            }
            body @ ResponseBodyData::NotFound => {
                // Bit of a mismatch to call this ResponseData,
                // as it will be replaced with a special page
                // that produces it's own HttpResponse
                Ok(ResponseData {
                    content_type: "text/html".into(),
                    is_page,
                    last_modified: None,
                    etag: None,
                    headers: Vec::new(),
                    body
                })
            }
            body @ ResponseBodyData::ErrorResponse(_, _) => {
                Ok(ResponseData {
                    content_type: "text/html".into(),
                    is_page,
                    last_modified: None,
                    etag: None,
                    headers: Vec::new(),
                    body
                })
            }
            // We only expect types from non-200 status code, the rest seems not to be
            _ =>  Err(ProxyError::actix("Expected non-200 response body"))
        }
    }
}
// Consider consolidating String and Bytes
/// This includes a bit more than response body data now,
/// 404's, redirects and errors
enum ResponseBodyData {
    StringBody(String, Option<WpCacheInfo>),
    BytesBody(web::Bytes, Option<WpCacheInfo>),
    Redirect(StatusCode, String),
    NotFound,
    ErrorResponse(StatusCode, String),
}
impl ResponseBodyData {
    pub fn from_non_200_status_code(
        status_code: StatusCode,
        body: web::BytesMut,
        replacements: Vec<(String, String)>,
        headers: &header::HeaderMap
    ) -> Self {
        match status_code {
            StatusCode::NOT_FOUND => ResponseBodyData::NotFound,
            StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT => {
                let location = header_string(headers, "Location");
                ResponseBodyData::Redirect(status_code, location)
            },
            // A bit simplified.., assuming error
            // This may work for a content site, but not an app 
            _ => {
                // For errors, we want to report information somewhere,
                // and not show users sensitive error information,
                // though inform as best as possible
                // For dev_mode, we want to show the error
                let body = match map_code_response_body(body, replacements, true) {
                    Ok(response_body) => match response_body {
                        ResponseBodyData::StringBody(body, _) => {
                            // We attempt to get a string body, and disregard wp cache info
                            // we want to replace url's in this
                            body
                        }
                        _ => "Error was not a string".into()
                    }
                    Err(_) => "Could not parse response".into()
                };
                ResponseBodyData::ErrorResponse(status_code, body)
            }
        }
    }
}

// Todo: This doesn't feel like a good abstraction/good code
// Especially with the special cases in the enum.

/// Pass-through does not error on non-200 status code,
/// todo: better handling. What we could use is not to cache errors,
/// but need better handling to check what is an actual error
/// This works ok at the front-end now, mod 404
fn map_client_body<'a>(
    status_code: StatusCode,
    headers: header::HeaderMap,
    content_type: String,
    body: web::BytesMut,
    replacements: Vec<(String, String)>,
    pass_through: bool
) -> Result<ResponseBodyData, Error> {
    if !pass_through && status_code != StatusCode::OK {
        return Ok(ResponseBodyData::from_non_200_status_code(status_code, body, replacements, &headers));
    }
    let content_type_first = match content_type.find(';') {
        Some(idx) => &content_type[0..idx],
        None => &content_type,
    };
    match content_type_first {
        "text/html" => map_code_response_body(body, replacements, true),
        "text/css" => map_code_response_body(body, replacements, false),
        "application/javascript" => map_code_response_body(body, replacements, true),
        "application/json" => map_code_response_body(body, replacements, true),
        "application/xml" => map_code_response_body(body, replacements, true),
        "text/plain" => map_code_response_body(body, replacements, true),
        _ => Ok(map_binary_body(body, replacements)),
    }
}

pub fn process_payload(
    payload: web::Payload,
    req: &HttpRequest,
    content_type: String,
    replacements: Vec<(String, String)>,
) -> impl Future<Item = web::Bytes, Error = Error> {
    let form_replacements = replacements.clone();
    let text_replacements = replacements.clone();
    match content_type.to_lowercase().as_ref() {
        "application/x-www-form-urlencoded" => Either::A(Either::A(
            decompressed(payload, req.headers())
                .map(|bytes| replace_form_data(&bytes, form_replacements).unwrap_or(bytes)),
        )),
        "multipart/form-data" => {
            let boundary = multipart_boundary(req.headers());
            match boundary {
                Ok(boundary) => {
                    // Multipart branch
                    let decompress =
                        actix_web::dev::Decompress::from_headers(payload, req.headers());
                    let multipart = Multipart::new(req.headers(), decompress);
                    let mut result = web::BytesMut::new();
                    // Add initial boundary
                    result.extend(b"\r\n");
                    result.extend(boundary.as_bytes());
                    // Fold multipart field stream
                    let parts = multipart
                        .map_err(Error::from)
                        .fold(
                            (result, replacements.clone(), boundary.clone()),
                            |(mut result, replacements, boundary), field| {
                                result.extend(b"\r\n");
                                // Add headers of part
                                field.headers().into_iter().for_each(|(name, value)| {
                                    // "Coerce" to string, can be "opaque bytes" per
                                    // https://docs.rs/actix-web/1.0.3/actix_web/http/header/struct.HeaderValue.html
                                    // anyway it may not be important to support passing such on in our case
                                    let value = match value.to_str() {
                                        Ok(str) => str.to_owned(),
                                        Err(_) => "".to_owned(),
                                    };
                                    result.extend(format!("{}: {}\r\n", name, value).bytes());
                                });
                                result.extend(b"\r\n");
                                // For form, and text content, do replacements
                                let replacements = replacements.clone();
                                let content_disposition = field.content_disposition();
                                field
                                    .map_err(Error::from)
                                    .fold(web::BytesMut::new(), move |mut body, chunk| {
                                        body.extend_from_slice(&chunk);
                                        Ok::<_, Error>(body)
                                    })
                                    .map(move |field_body| {
                                        let bytes = field_body.freeze();
                                        match content_disposition {
                                            Some(content_disposition) => {
                                                // todo: Other cases to include here?
                                                if content_disposition.is_form_data() {
                                                    // todo: could consider error on err
                                                    match replace_form_data(
                                                        &bytes,
                                                        replacements.clone(),
                                                    ) {
                                                        Ok(body) => result.extend(body),
                                                        Err(_) => result.extend(bytes),
                                                    };
                                                } else {
                                                    result.extend(bytes);
                                                }
                                            }
                                            None => {
                                                result.extend(bytes);
                                            }
                                        }
                                        // Add boundary
                                        result.extend(b"\r\n");
                                        result.extend(boundary.as_bytes());
                                        (result, replacements, boundary)
                                    })
                            },
                        )
                        .map(|(result, _replacements, _boundary)| result.freeze());
                    Either::A(Either::B(parts))
                }
                Err(_) => Either::B(Either::B(payload_to_bytes(payload))),
            }
        }
        "application/json" |
        "text/plain" => {
            Either::B(Either::A(payload_to_bytes(payload).map(
                |bytes| match String::from_utf8(bytes.to_vec()) {
                    Ok(string) => {
                        let replaced = replace_urls_rev(string, text_replacements, false);
                        web::Bytes::from(replaced.as_bytes())
                    }
                    Err(_) => bytes,
                },
            )))
        }
        _ => {
            // Pass through
            Either::B(Either::B(payload_to_bytes(payload)))
        }
    }
}

// hm, just added this to util
fn payload_to_bytes(payload: web::Payload) -> impl Future<Item = web::Bytes, Error = Error> {
    payload
        .map_err(Error::from)
        .fold(web::BytesMut::new(), move |mut body, chunk| {
            body.extend_from_slice(&chunk);
            Ok::<_, Error>(body)
        })
        .map(|body| body.freeze())
}

// Also make one without replacements or integrate? the other could stream
pub fn do_request_forward(
    data: web::Data<AppData>,
    req: HttpRequest,
    payload: web::Payload,
    path_config: PathConfigKey,
    dev_mode: Mode
) -> impl Future<Item = HttpResponse, Error = Error> {
    // A copy of pathConfig. todo: possibly make a lifetime
    let path_config = match get_path_config(&data, &path_config) {
        Ok(p) => p,
        Err(e) => return Either::A(future::err(e)),
    };
    let replacements = path_config.replacements.clone();
    let rev_replacements = rev_replacements(replacements.clone());
    let url_path = crate::Alias::process(&path_config.aliases, req.match_info().query("url_path"));
    let url_path = {
        let with_query = match req.uri().query() {
            Some(query) => {
                url_path
                    + "?"
                    + query
            }
            None => url_path,
        };
        // todo: Hash, though as a proxy it probably doesn't matter much
        // the problem is I can't find a method to get it out of uri
        replace_in_url(&with_query, &rev_replacements)
    };
    let request_url = path_config.request_base + "/" + &url_path;
    let content_type = header_string(req.headers(), "content-type");
    let payload = process_payload(payload, &req, content_type, replacements.clone());
    // actix uses payload.take(), investigate
    // Actix examples pass this is data(), so may have some advantages
    let client = Client::default();
    //println!("Request: {}", request_url);
    // We need to replace the other way around for
    // form data and request parameters
    let head = req.head();
    let mut freq = client
        .request(head.method.clone(), request_url)
        .timeout(std::time::Duration::new(30, 0))
        .header("x-is-proxy", "1")
        ;
    // It seems cookies are split into several headers which
    // causes problems when php is parsing into $_COOKIE,
    // so collecting cookie headers and concatinating them
    // in the format required by php
    let mut cookies = Vec::new();
    for (key, value) in head.headers.into_iter() {
        // https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
        freq = match key.as_str().to_lowercase().as_str() {
            // Special cookie handling
            "cookie" => {
                match value.to_str() {
                    Ok(value) => {
                        cookies.push(value.to_owned());
                    }
                    Err(_) => ()
                }
                freq
            }
            // Headers to pass on
            "accept"
            | "accept-charset"
            | "accept-datetime"
            | "accept-encoding"
            | "accept-language"
            | "access-control-request-method"
            | "access-control-request-headers"
            | "authorization"
            | "cache-control"
            | "content-type"
            | "date"
            | "expect"
            | "from"
            | "if-match"
            | "if-modified-since"
            | "if-none-match"
            | "if-range"
            | "if-unmodified-since"
            | "pragma"
            | "range"
            | "te"
            | "trailer"
            | "user-agent"
            // Useful for websocket, but unsure if this may be used to upgrade to https (which we wouldn't want)?
            | "upgrade"
            | "sec-fetch-mode"
            | "sec-fetch-site"
            // Important for wp-json, a custom wp header with a nonce
            | "x-wp-nonce"
            => freq.header(key, value.to_owned()),
            // Replace simple urls from in "reverse"
            "origin"
            => {
                match value.to_str() {
                    Ok(value) => {
                        freq.header(key, replace_urls_rev(String::from(value), replacements.clone(), false))
                    }
                    Err(_) => freq
                }
            },
            // Replace url and possibly query params
            "referer"
            => {
                match value.to_str() {
                    Ok(value) => {
                        freq.header(key, replace_in_url(value, &rev_replacements))
                    }
                    Err(_) => freq
                }
            }
            // Headers to ignore
            "upgrade-insecure-requests"
            | "content-length"
            | "forwarded"
            // Host will be explicitly set
            | "host"
            | "http2-settings"
            | "max-forwards"
            | "proxy-authorization"
            // I think we can just as well transfer from the same network
            | "transfer-encoding"
            | "via"
            | "warning"
            // I don't think keep alive is needed. Possibly it would make sense to
            // pass proxy information in this
            | "connection"
            => freq,
            _ => {
                // to get some overview
                println!("Unrecognized header: {:?}, {:?}", key, value);
                freq.header(key, value.to_owned())
            }
        };
    }
    // Set collected cookies
    freq = freq.set_header("cookie", cookies.join("; "));
    // Set host header in any case. This is not used with http2
    freq = freq.set_header("host", data.proxied.clone());
    freq = freq.set_header("HTTP_X_FORWARDED_PROTO", "https");
    //let freq = freq.no_decompress();
    /*
    let freq = if let Some(addr) = req.head().peer_addr {
        //println!("Setting forwarded for: {:?}", addr);
        //freq.header("x-forwarded-for", format!("{}", addr.ip()))
        freq
    } else {
        freq
    };*/
    Either::B(payload.and_then(move |body| {
        freq
            .send_body(body)
            .map_err(Error::from)
            .and_then(move |resp| {
                //println!("Status {:?}", resp.status());
                let mut client_resp = HttpResponse::build(resp.status());
                // todo: probably encode in given encoding? Although to
                // socket on same host decompressed might be good
                for (header_name, header_value) in resp.headers().iter().filter(|(h, _)| {
                    *h != "connection" && *h != "content-length" && *h != "content-encoding"
                    && *h != "upgrade-insecure-requests"
                    && (!dev_mode.dev_or_admin() || *h != "cache-control")
                }) {
                    let header_value = if *header_name == "location" || *header_name == "Location" {
                        match header_value.to_str() {
                            Ok(value) => {
                                match HeaderValue::from_str(&replace_in_url(
                                    value,
                                    &replacements
                                )) {
                                    Ok(header) => header.clone(),
                                    Err(_) => header_value.clone(),
                                }
                            }
                            Err(_) => header_value.clone(),
                        }
                    } else {
                        header_value.clone()
                    };
                    client_resp.header(header_name.clone(), header_value);
                }
                // When dev-mode go for revalidation
                if dev_mode.dev_or_admin() {
                    client_resp.set_header("cache-control", "no-cache, must-revalidate, max-age=0");
                }
                let status_code = resp.status().clone();
                client_resp.status(status_code.clone());
                let content_type = header_string(resp.headers(), "content-type");
                let headers = resp.headers().to_owned();
                resp.from_err()
                    .fold(BytesMut::new(), |mut acc, chunk| {
                        acc.extend_from_slice(&chunk);
                        Ok::<_, Error>(acc)
                    })
                    .and_then(move |body| {
                        // todo: streaming replacements
                        match map_client_body(status_code, headers, content_type, body, replacements, true) {
                            Ok(body_data) => match body_data {
                                ResponseBodyData::BytesBody(bytes, _cache_info) => {
                                    Either::A(future::ok(client_resp.body(bytes)))
                                }
                                ResponseBodyData::StringBody(string, _cache_info) => {
                                    Either::A(future::ok(client_resp.body(string)))
                                }
                                ResponseBodyData::Redirect(_status_code, _location) => {
                                    // Headers should already be set above
                                    Either::A(future::ok(client_resp.body("".to_string())))
                                }
                                ResponseBodyData::NotFound => {
                                    Either::B(Either::A(not_found_page(data, req, dev_mode)))
                                }
                                ResponseBodyData::ErrorResponse(_status_code, error_body) => {
                                    if dev_mode.dev_or_admin() {
                                        Either::A(future::ok(client_resp.body(error_body)))
                                    } else {
                                        // Here we want to get a generic error page
                                        Either::B(Either::B(error_page(data, req, dev_mode)))
                                    }
                                },
                            },
                            Err(e) => Either::A(future::err(e))
                        }
                    })
            })
    }))
}

/// Returning a reference would be preferable in itself,
/// This might require a read lock?
fn get_path_config(
    data: &web::Data<AppData>,
    path_config: &PathConfigKey,
) -> Result<PathConfig, Error> {
    let read_lock = match data.path_configs.read() {
        Ok(read_lock) => read_lock,
        Err(_e) => return Err(ProxyError::new("Could not aqcuire read lock").into()),
    };
    match read_lock.get(path_config) {
        Some(path_config) => Ok(path_config.to_owned()),
        None => {
            Err(ProxyError::new(format!("Could not find path config for {}", path_config.0)).into())
        }
    }
}

pub fn not_found_page(
    data: web::Data<AppData>,
    req: HttpRequest,
    dev_mode: Mode
) -> impl Future<Item = HttpResponse, Error = Error> {
    let url_path = data.not_found_page.to_owned();
    do_special_page(data, req, PathConfigKey("".into()), url_path, StatusCode::NOT_FOUND, dev_mode)
}

pub fn error_page(
    data: web::Data<AppData>,
    req: HttpRequest,
    dev_mode: Mode
) -> impl Future<Item = HttpResponse, Error = Error> {
    let url_path = data.error_page.to_owned();
    do_special_page(data, req, PathConfigKey("".into()), url_path, StatusCode::INTERNAL_SERVER_ERROR, dev_mode)
}

/// Version of standard request to get a special page,
/// currently 404 and error
/// This is different from a client request in that it
/// will use caching and expect a StringBody
/// We want it to be fast in case of bots or something
pub fn do_special_page(
    data: web::Data<AppData>,
    req: HttpRequest,
    path_config_key: PathConfigKey,
    url_path: String,
    status_code: StatusCode,
    dev_mode: Mode,
) -> impl Future<Item = HttpResponse, Error = Error> {
    let path_config = match get_path_config(&data, &path_config_key) {
        Ok(p) => p,
        Err(e) => return Either::A(future::err(e)),
    };
    let cached = if dev_mode.dev_or_admin() {
        None
    } else {
        let read_cache = data.cache.read().unwrap();
        let cached = read_cache.get(&url_path);
        cached.map(|v| v.to_owned())
    };
    // Mostly html assumed expected, could possibly be json also
    let request_url = path_config.request_base + "/" + &url_path;
    let page_exp_minute_interval = if dev_mode.dev_or_admin() {
        0
    } else {
        // Special pages need not the short expire of normal pages,
        // for now. But keeping the option open of dynamic 404's etc
        60 * 10
    };
    let replacements = path_config.replacements.clone();
    let preload_replacements = replacements.clone();
    let cache_dir = data.cache_dir.clone();
    match cached {
        Some(cache) => {
            // Passing `None` for if_none_matches in this branch
            // as it has already been tested
            Either::A(match cache.data {
                CacheEntryData::Text(cache_file) => {
                    let mut resp = HttpResponse::build(status_code);
                    resp.content_type("text/html");
                    if let Some(preloads) = cache.preloads {
                        resp.header("Link", preloads);
                    }
                    match std::fs::read_to_string(cache_file) {
                        Ok(contents) => future::ok(resp.body(contents)),
                        Err(e) => future::err(ProxyError::actix(format!("Could not read cache file: {:?}", e)))
                    }
                }
                _ => future::err(ProxyError::actix("Non-text special page"))
            })
        }
        None => {
            Either::B(do_client_request(request_url, true)
                .and_then(move |resp| {
                    if resp.status() != StatusCode::OK {
                        return Either::A(future::err(ProxyError::actix("Special page did not return status 200")));
                    }
                    let (content_type_first, content_type) = simple_content_type(resp.headers());
                    // Going directly to map_code_response is important in not creating
                    // a recursive type, where Future type gets into a loop
                    match content_type_first.as_str() {
                        "text/html" => Either::B(map_code_response(
                            resp,
                            content_type,
                            replacements,
                            true,
                        )),
                        _ => Either::A(future::err(ProxyError::actix(format!("Special page was not text/html, but: {}", content_type_first))))
                    }
                })
                .and_then(move |resp| {
                    match resp.body {
                        ResponseBodyData::StringBody(body, cache_info) => {
                            let preloads = cache_info.as_ref().and_then(|cache_info| {
                                make_preload_header(&cache_info.preloads, preload_replacements)
                            });
                            let cache_file = match write_cache_file(url_path.clone(), body.as_bytes(), cache_dir) {
                                Ok(cache_file) => cache_file,
                                Err(_) => return future::err(ProxyError::actix("Failed to write cache file"))
                            };
                            replace_cache_entry(
                                url_path,
                                path_config_key,
                                CacheEntryData::Text(cache_file.clone()),
                                resp.content_type,
                                resp.is_page,
                                resp.last_modified,
                                resp.etag,
                                resp.headers,
                                preloads.clone(),
                                cache_info,
                                data,
                            );
                            // And a simple response
                            let mut resp = HttpResponse::build(status_code);
                            resp.content_type("text/html");
                            if let Some(preloads) = preloads {
                                resp.header("Link", preloads);
                            }
                            let file_contents = match std::fs::read_to_string(cache_file) {
                                Ok(contents) => contents,
                                Err(_) => return future::err(ProxyError::actix("Could not read cache file"))
                            };
                            future::ok(resp.body(file_contents))
                        }
                        _ => future::err(ProxyError::actix("Non string body in special page"))
                    }
                }))
        },
    }
}

/// Standard request getting url from `url_path`
/// and using a given pathConfig
pub fn do_request_std(
    data: web::Data<AppData>,
    req: HttpRequest,
    payload: web::Payload,
    path_config: PathConfigKey,
    dev_mode: Mode
) -> impl Future<Item = HttpResponse, Error = Error> {
    // A copy of pathConfig. todo: possibly make a lifetime
    let path_config_data = match get_path_config(&data, &path_config) {
        Ok(p) => p,
        Err(e) => return Either::B(Either::B(Either::A(future::err(e)))),
    };
    let url_path = crate::Alias::process(&path_config_data.aliases, req.match_info().query("url_path"));
    if path_config_data.forward.contains(&url_path) {
        return Either::A(Either::A(do_request_forward(
            data,
            req,
            payload,
            path_config,
            dev_mode
        )));
    }
    // todo: With intertwinded paths, consider existing entries
    if let Some(static_paths) = &path_config_data.static_paths {
        // We have a path we can use to access files
        // from the file system
        // Check if already resolved
        // todo: Could be a bit cleaned up with option combinators?
        // maybe move to function
        let resolved = {
            println!("Checking {}", &url_path);
            let static_resolved_read = data.static_resolved.read().unwrap();
            if let Some(static_resolved) = static_resolved_read.get(&url_path) {
                // Has been resolved, can still be non-static file
                match static_resolved {
                    Some(static_resolved) => {
                        match &static_resolved.if_webp {
                            Some(webp_file) => {
                                match req
                                    .headers()
                                    .get(header::ACCEPT)
                                    .and_then(|hv| hv.to_str().ok())
                                {
                                    Some(accept) if accept.contains("image/webp") => {
                                        // Serve webp
                                        return Either::B(Either::A(future::result(
                                            serve_static_file(
                                                req,
                                                webp_file.as_path(),
                                                data.img_exp_minute_interval,
                                            )
                                            .map_err(Error::from),
                                        )));
                                    }
                                    _ => {
                                        return Either::B(Either::A(future::result(
                                            serve_static_file(
                                                req,
                                                static_resolved.file.as_path(),
                                                data.img_exp_minute_interval,
                                            )
                                            .map_err(Error::from),
                                        )));
                                    }
                                }
                            }
                            None => {
                                // Straight static file
                                return Either::B(Either::A(future::result(
                                    serve_static_file(
                                        req,
                                        static_resolved.file.as_path(),
                                        data.img_exp_minute_interval,
                                    )
                                    .map_err(Error::from),
                                )));
                            }
                        }
                    }
                    None => {
                        // Resolved to not a static file
                        true
                    }
                }
            } else {
                println!("Not resolved");
                false
            }
        };
        if !resolved {
            // Not found in resolved cache, do resolve
            use std::path;
            let pathinfo = path::Path::new(&url_path);
            let mut path_matched = false;
            for (path, static_path) in static_paths {
                let check_path = path::Path::new(path);
                if pathinfo.starts_with(check_path) {
                    path_matched = true;
                    // We found matched request path
                    let file_path = match pathinfo.strip_prefix(check_path) {
                        Ok(stripped) => path::Path::new(static_path).join(stripped),
                        Err(_) => {
                            return Either::A(Either::B(future::err(Error::from(ProxyError::new(
                                "Path error",
                            )))))
                        }
                    };
                    // For images, we can serve webp images when they
                    // exist instead of jpeg/png/gif
                    // For js and css, we could fetch directly
                    // though replacements is needed (passing for now)
                    let resolved = match file_path.extension().and_then(|e| e.to_str()) {
                        Some(ext) => match ext {
                            "jpg" | "jpeg" | "png" | "gif" => {
                                // Check for webp
                                // todo, ensure this is below root
                                let mut webp_path = path::PathBuf::from(file_path.clone());
                                webp_path.set_extension("webp");
                                if webp_path.exists() {
                                    Some(StaticResolved {
                                        file: file_path,
                                        if_webp: Some(webp_path),
                                    })
                                } else {
                                    Some(StaticResolved {
                                        file: file_path,
                                        if_webp: None,
                                    })
                                }
                            }
                            "webp" | "pdf" | "zip" | "webm" | "mp4" => {
                                // Todo: First, `img_exp..` is semantic mismatch to zip etc,
                                // and possibly these (especially zip) may be different
                                // (content disposition attachment)
                                Some(StaticResolved {
                                    file: file_path,
                                    if_webp: None,
                                })
                            }
                            _ => None,
                        },
                        None => None,
                    };
                    {
                        let mut static_resolved_write = data.static_resolved.write().unwrap();
                        static_resolved_write.insert(url_path.clone(), resolved.clone());
                    }
                    match resolved {
                        Some(static_path) => {
                            let serve_file = match static_path.if_webp {
                                Some(webp_path) => {
                                    match req
                                        .headers()
                                        .get(header::ACCEPT)
                                        .and_then(|hv| hv.to_str().ok())
                                    {
                                        Some(accept) if accept.contains("image/webp") => webp_path,
                                        _ => static_path.file,
                                    }
                                }
                                None => static_path.file,
                            };
                            return Either::B(Either::A(future::result(
                                serve_static_file(
                                    req,
                                    serve_file.as_path(),
                                    data.img_exp_minute_interval,
                                )
                                .map_err(Error::from),
                            )));
                        }
                        None => (),
                    }
                }
            }
            if !path_matched {
                let mut static_resolved_write = data.static_resolved.write().unwrap();
                static_resolved_write.insert(url_path.clone(), None);
            }
        }
    }
    let url_path_with_query = match req.uri().query() {
        Some(query) => url_path + "?" + query,
        None => url_path,
    };
    Either::B(Either::B(Either::B(do_request(
        data,
        req,
        url_path_with_query,
        path_config_data,
        dev_mode
    ))))
}

fn serve_static_file(
    req: HttpRequest,
    path: &std::path::Path,
    exp_minute_interval: u32,
) -> io::Result<HttpResponse> {
    // Much from https://github.com/actix/actix-web/blob/master/actix-files/src/named.rs
    use actix_web::http::header::{ContentDisposition, DispositionParam, DispositionType, CacheDirective};
    use actix_web::HttpMessage;
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    // Last modified
    let last_modified = metadata.modified()?;
    // Mime
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    // Filename
    let filename = match path.file_name() {
        Some(name) => name.to_string_lossy(),
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Provided path has no filename",
            ));
        }
    };
    // Content disposition (attachment or inline)
    // Should possibly only add it when attachment
    let disposition_type = match mime.type_() {
        mime::IMAGE | mime::TEXT | mime::VIDEO => DispositionType::Inline,
        _ => DispositionType::Attachment,
    };
    let cd = ContentDisposition {
        disposition: disposition_type,
        parameters: vec![DispositionParam::Filename(filename.into_owned())],
    };
    // Return early if last-modified headers gives hit
    // TODO!: What about IfModifiedSince
    if let Some(header::IfModifiedSince(ref since)) = req.get_header() {
        let since: SystemTime = since.clone().into();
        let serve_new = match (
            last_modified.duration_since(UNIX_EPOCH),
            since.duration_since(UNIX_EPOCH),
        ) {
            (Ok(last_modified), Ok(since)) => {
                println!("lm: {:?}, since: {:?}", last_modified, since);
                last_modified > since
            }
            _ => true,
        };
        // Todo: Disabled to avoid 304 issues
        if false && !serve_new {
            let mut resp = HttpResponse::NotModified();
            resp.set(header::ContentType(mime));
            resp.set(header::LastModified(HttpDate::from(last_modified)));
            if let Some((next_expire, max_age)) = next_expire(exp_minute_interval) {
                // todo: Factor out cache header function?
                resp.set(header::Expires(HttpDate::from(next_expire)));
                resp.set(header::CacheControl(vec![
                    CacheDirective::MaxAge(max_age)
                ]));
            }
            resp.header(header::CONTENT_DISPOSITION, cd);
            return Ok(resp.finish());
        }
    }
    let length = metadata.len();
    let mut resp = HttpResponse::Ok();
    resp.set(header::LastModified(HttpDate::from(last_modified)));
    resp.set(header::ContentType(mime));
    if let Some((next_expire, max_age)) = next_expire(exp_minute_interval) {
        resp.set(header::Expires(HttpDate::from(next_expire)));
        resp.set(header::CacheControl(vec![
            CacheDirective::MaxAge(max_age)
        ]));
    }
    resp.header(header::CONTENT_DISPOSITION, cd);
    let ranges = req
        .headers()
        .get(&actix_web::http::header::RANGE)
        .map(|h| h.to_owned());
    Ok(file_body(resp, ranges, file, length))
}

/// Typical request pipeline with caching
/// url_path is used as key
fn do_request(
    data: web::Data<AppData>,
    req: HttpRequest,
    url_path: String,
    path_config: PathConfig,
    dev_mode: Mode
) -> impl Future<Item = HttpResponse, Error = Error> {
    // Check cache, return `not modified` if etag matches
    let cached = {
        if dev_mode.dev_or_admin() {
            None
        } else {
            let read_cache = data.cache.read().unwrap();
            let cached = read_cache.get(&url_path.to_owned());
            // Return early if etag match to avoid
            // cloning the body
            // todo: Disabling this currently because some ios/issues, "protocol error"
            if false {
            if let Some(cache) = cached {
                if let Some(etag) = &cache.etag {
                    match header_opt(req.headers(), "If-None-Match") {
                        Some(if_none_match) => {
                            if &if_none_match == etag {
                                // Send a log entry if this is a page
                                if cache.is_page {
                                    log_visit_server(&url_path, &req, &data.log_actor);
                                }
                                println!("{:?}", req.headers());
                                return Either::A(future::ok(to_not_modified(
                                    cache.content_type.clone(),
                                    cache.last_modified.clone(),
                                    cache.etag.clone(),
                                    cache.preloads.clone(),
                                    data.page_exp_minute_interval,
                                )));
                            }
                        }
                        None => (),
                    }
                }
            }
            }
            cached.map(|v| v.to_owned())
        }
    };
    let request_url = path_config.request_base + "/" + &url_path;
    let ranges = req
        .headers()
        .get(&actix_web::http::header::RANGE)
        .map(|h| h.to_owned());
    let page_exp_minute_interval = if dev_mode.dev_or_admin() {
        0
    } else {
        data.page_exp_minute_interval
    };
    let img_exp_minute_interval = data.img_exp_minute_interval;
    match cached {
        Some(cache) => {
            // Passing `None` for if_none_matches in this branch
            // as it has already been tested
            match cache.data {
                CacheEntryData::Text(cache_file) => {
                    // Check for expiration
                    match cache.expire {
                        None => {
                            // Making sure to only log visit once, as it's also done in reload_cache_and_response
                            if cache.is_page {
                                log_visit_server(&url_path, &req, &data.log_actor);
                            }
                            Either::B(Either::A(future::result(
                                cache_file_response(
                                    cache.content_type,
                                    cache.last_modified,
                                    cache.etag,
                                    cache.headers,
                                    None,
                                    cache.preloads,
                                    StatusCode::OK,
                                    cache_file,
                                    ranges,
                                    page_exp_minute_interval,
                                )
                                .map_err(Error::from),
                            )))
                        },
                        Some(expire) => {
                            use chrono::prelude::*;
                            let now = Local::now().timestamp();
                            if expire < now {
                                // Expired, fetch new
                                Either::B(Either::B(reload_cache_and_response(
                                    req,
                                    url_path,
                                    path_config.key,
                                    request_url,
                                    path_config.replacements,
                                    path_config.fold_redirects,
                                    None,
                                    data,
                                    ranges,
                                    page_exp_minute_interval,
                                    dev_mode
                                )))
                            } else {
                                if cache.is_page {
                                    log_visit_server(&url_path, &req, &data.log_actor);
                                }
                                Either::B(Either::A(future::result(
                                    cache_file_response(
                                        cache.content_type,
                                        cache.last_modified,
                                        cache.etag,
                                        cache.headers,
                                        None,
                                        cache.preloads,
                                        StatusCode::OK,
                                        cache_file,
                                        ranges,
                                        page_exp_minute_interval,
                                    )
                                    .map_err(Error::from),
                                )))
                            }
                        }
                    }
                }
                CacheEntryData::Binary(cache_file) => Either::B(Either::A(future::result(
                    cache_file_response(
                        cache.content_type,
                        cache.last_modified,
                        cache.etag,
                        cache.headers,
                        None,
                        cache.preloads,
                        StatusCode::OK,
                        cache_file,
                        ranges,
                        img_exp_minute_interval,
                    )
                    .map_err(Error::from),
                ))),
            }
        }
        None => {
            let if_none_match = header_opt(req.headers(), "If-None-Match");
            Either::B(Either::B(reload_cache_and_response(
                req,
                url_path,
                path_config.key,
                request_url,
                path_config.replacements,
                path_config.fold_redirects,
                if_none_match,
                data,
                ranges,
                page_exp_minute_interval,
                dev_mode
            )))
        },
    }
}

/// Creates ResponseData from ClientResponse
fn branch_content_type<'a>(
    resp: awc::ClientResponse<impl Stream<Item = web::Bytes, Error = client::PayloadError> + 'a>,
    replacements: Vec<(String, String)>,
) -> impl Future<Item = ResponseData, Error = Error> + 'a {
    let status_code = resp.status();
    if status_code != StatusCode::OK {
        // Extract body at this point
        // This is also done in map_code_response and map_binary_response, so this seems the right
        // place approximately as these should be mutually exclusive
        // It is placed in error response at least

        // Need to clone headers here, would be nice to take them besides body stream
        let headers = resp.headers().to_owned();
        return Either::B(
            resp.from_err()
                .fold(BytesMut::new(), |mut acc, chunk| {
                    acc.extend_from_slice(&chunk);
                    Ok::<_, Error>(acc)
                })
                .and_then(move |body| {
                    ResponseData::from_non_200_status_code(status_code, body, replacements, &headers)
                })
        );
    }
    let (content_type_first, content_type) = simple_content_type(resp.headers());
    match content_type_first.as_str() {
        "text/html" => Either::A(Either::A(map_code_response(
            resp,
            content_type,
            replacements,
            true,
        ))),
        "text/css" => Either::A(Either::A(map_code_response(
            resp,
            content_type,
            replacements,
            false,
        ))),
        "application/javascript"
        | "application/json" => Either::A(Either::A(map_code_response(
            resp,
            content_type,
            replacements,
            true,
        ))),
        "text/plain" => Either::A(Either::A(map_code_response(
            resp,
            content_type,
            replacements,
            true,
        ))),
        _ => Either::A(Either::B(map_binary(resp, content_type, replacements))),
    }
}

fn make_preload_header(
    preloads: &Vec<PreloadLink>,
    replacements: Vec<(String, String)>,
) -> Option<String> {
    if preloads.len() > 0 {
        let mut links = Vec::new();
        for preload in preloads {
            // todo: better would be to replace only from beginning
            match preload {
                PreloadLink::Style(src, _) => links.push(format!(
                    "<{}>; rel=preload; as=style",
                    replace_urls(src.clone(), replacements.clone(), false)
                )),
                PreloadLink::Script(src, _) => links.push(format!(
                    "<{}>; rel=preload; as=script",
                    replace_urls(src.clone(), replacements.clone(), false)
                )),
                PreloadLink::Image(src, _) => links.push(format!(
                    "<{}>; rel=preload; as=image",
                    replace_urls(src.clone(), replacements.clone(), false)
                )),
                PreloadLink::Font(src, _) => links.push(format!(
                    "<{}>; rel=preload; crossorigin=anonymous; as=font",
                    replace_urls(src.clone(), replacements.clone(), false)
                )),
            }
        }
        Some(links.join(", "))
    } else {
        None
    }
}

/// Reloads a single cache entry, without returning the response
/// This is ran in response to cache invalidation from wp
fn reload_cache_entry(
    url_path: String,
    path_config: PathConfigKey,
    request_url: String,
    replacements: Vec<(String, String)>,
    fold_redirects: bool,
    data: web::Data<AppData>,
) -> impl Future<Item = (), Error = Error> {
    println!("Reloading {:?}", request_url);
    let preload_replacements = replacements.clone();
    let cache_dir = data.cache_dir.clone();
    do_client_request(request_url, fold_redirects)
        .and_then(move |resp| branch_content_type(resp, replacements))
        .and_then(move |resp| match resp.body {
            ResponseBodyData::StringBody(body, cache_info) => {
                let preloads = cache_info.as_ref().and_then(|cache_info| {
                    make_preload_header(&cache_info.preloads, preload_replacements)
                });
                let cache_file = write_cache_file(url_path.clone(), body.as_bytes(), cache_dir)?;
                replace_cache_entry(
                    url_path,
                    path_config,
                    CacheEntryData::Text(cache_file),
                    resp.content_type,
                    resp.is_page,
                    resp.last_modified,
                    resp.etag,
                    resp.headers,
                    preloads,
                    cache_info,
                    data,
                );
                Ok(())
            }
            ResponseBodyData::BytesBody(body, cache_info) => {
                let preloads = cache_info.as_ref().and_then(|cache_info| {
                    make_preload_header(&cache_info.preloads, preload_replacements)
                });
                let cache_file = write_cache_file(url_path.clone(), &body, cache_dir)?;
                replace_cache_entry(
                    url_path,
                    path_config,
                    CacheEntryData::Binary(cache_file),
                    resp.content_type,
                    resp.is_page,
                    resp.last_modified,
                    resp.etag,
                    resp.headers,
                    preloads,
                    cache_info,
                    data,
                );
                Ok(())
            }
            ResponseBodyData::Redirect(_status_code, _location) => Ok(()),
            ResponseBodyData::NotFound => {
                // Silently ignoring errors now
                match clear_cache_entry(&data, url_path) {
                    Ok(_) => (),
                    Err(_) => ()
                }
                Ok(())
            },
            ResponseBodyData::ErrorResponse(_status_code, _error) => {
                // We clear cache entry, (and do not save the error response in case it will be fixed)
                match clear_cache_entry(&data, url_path) {
                    Ok(_) => (),
                    Err(_) => ()
                }
                Ok(())
            },
        })
}

fn clear_cache_entry(
    data: &web::Data<AppData>,
    url_path: String,
) -> Result<(), ()> {
    {
        let read = match data.cache.read() {
            Ok(read) => read,
            Err(_) => return Err(())
        };
        if !read.contains_key(&url_path) {
            return Ok(());
        }
    };
    let mut write_cache = match data.cache.write() {
        Ok(write_cache) => write_cache,
        Err(_) => return Err(())
    };
    write_cache.remove(&url_path);
    Ok(())
}

// For dev mode we don't want to cache pages, so taking page_exp_minute_interval
/// Reloads the cache and returns a HttpResponse
/// Useful when a refreshed response is needed during a request
fn reload_cache_and_response(
    req: HttpRequest,
    url_path: String,
    path_config: PathConfigKey,
    request_url: String,
    replacements: Vec<(String, String)>,
    fold_redirects: bool,
    if_none_matches: Option<String>,
    data: web::Data<AppData>,
    ranges: Option<HeaderValue>,
    page_exp_minute_interval: u32,
    dev_mode: Mode,
) -> impl Future<Item = HttpResponse, Error = Error> {
    let preload_replacements = replacements.clone();
    let header_replacements = replacements.clone();
    let cache_dir = data.cache_dir.clone();
    let img_exp_minute_interval = data.img_exp_minute_interval;
    do_client_request(request_url, fold_redirects)
        .and_then(move |resp| branch_content_type(resp, replacements))
        .and_then(move |resp| {
            let etag = match resp.etag {
                Some(etag) => Some(etag),
                None => {
                    // Simple etag with current timestamp
                    use chrono::prelude::*;
                    let now = Local::now().timestamp();
                    Some(format!("{}", now))
                }
            };
            let content_type = resp.content_type.clone();
            let last_modified = resp.last_modified.clone();
            let headers = resp.headers.clone();
            let is_page = resp.is_page;
            if is_page {
                log_visit_server(&url_path, &req, &data.log_actor);
            }
            match resp.body {
                ResponseBodyData::StringBody(body, cache_info) => {
                    let preloads = cache_info.as_ref().and_then(|cache_info| {
                        make_preload_header(&cache_info.preloads, preload_replacements)
                    });
                    Either::A(Either::A(
                        future::result(
                            write_cache_file(url_path.clone(), body.as_bytes(), cache_dir)
                                .map_err(Error::from),
                        )
                        .and_then(move |cache_file| {
                            replace_cache_entry(
                                url_path,
                                path_config,
                                CacheEntryData::Text(cache_file.clone()),
                                content_type.clone(),
                                is_page,
                                last_modified.clone(),
                                etag.clone(),
                                headers.clone(),
                                preloads.clone(),
                                cache_info,
                                data,
                            );
                            future::result(
                                cache_file_response(
                                    content_type,
                                    last_modified,
                                    etag,
                                    headers,
                                    if_none_matches,
                                    preloads,
                                    StatusCode::OK,
                                    cache_file,
                                    ranges,
                                    page_exp_minute_interval,
                                )
                                .map_err(Error::from),
                            )
                        }),
                    ))
                }
                ResponseBodyData::BytesBody(body, cache_info) => {
                    let preloads = cache_info.as_ref().and_then(|cache_info| {
                        make_preload_header(&cache_info.preloads, preload_replacements)
                    });
                    Either::A(Either::B(
                        future::result(
                            write_cache_file(url_path.clone(), &body, cache_dir)
                                .map_err(Error::from),
                        )
                        .and_then(move |cache_file| {
                            replace_cache_entry(
                                url_path,
                                path_config,
                                CacheEntryData::Binary(cache_file.clone()),
                                content_type.clone(),
                                is_page,
                                last_modified.clone(),
                                etag.clone(),
                                headers.clone(),
                                preloads.clone(),
                                cache_info,
                                data,
                            );
                            future::result(
                                cache_file_response(
                                    content_type,
                                    last_modified,
                                    etag,
                                    headers,
                                    if_none_matches,
                                    preloads,
                                    StatusCode::OK,
                                    cache_file,
                                    ranges,
                                    img_exp_minute_interval,
                                )
                                .map_err(Error::from),
                            )
                        }),
                    ))
                }
                ResponseBodyData::Redirect(status_code, location) => {
                    let mut client_resp = HttpResponse::build(status_code);
                    match HeaderValue::from_str(&replace_urls(
                        location,
                        header_replacements.clone(),
                        false
                    )) {
                        Ok(header) => {
                            let _ = client_resp.header("location", header);
                        },
                        Err(_) => ()
                    }
                    Either::B(Either::A(future::ok(client_resp.finish())))
                }
                ResponseBodyData::NotFound => {
                    // todo: Log
                    Either::B(Either::B(Either::A(not_found_page(data, req, dev_mode))))
                }
                ResponseBodyData::ErrorResponse(status_code, error_body) => {
                    // todo: Log
                    if dev_mode.dev_or_admin() {
                        // When dev mode, show the error we got (it's possibly an empty page though
                        // when logged in on prod)
                        let mut client_resp = HttpResponse::build(status_code);
                        Either::B(Either::A(future::ok(client_resp.body(error_body))))
                    } else {
                        // Here we want to get a generic error page
                        Either::B(Either::B(Either::B(error_page(data, req, dev_mode))))
                    }
                }
            }
        })
}

fn write_cache_file(url_path: String, body: &[u8], cache_dir: String) -> io::Result<String> {
    let mut hasher = DefaultHasher::new();
    url_path.hash(&mut hasher);
    let filename = format!("{}/{:x}", &cache_dir, &hasher.finish());
    let mut file = fs::File::create(&filename)?;
    file.write_all(body)?;
    Ok(filename)
}

/// Given a response parsed for cache_info,
/// replace in the cache and clean up based
/// on previous entrys cache_info
fn replace_cache_entry(
    url_path: String,
    path_config: PathConfigKey,
    body: CacheEntryData,
    content_type: String,
    is_page: bool,
    last_modified: Option<String>,
    etag: Option<String>,
    headers: Vec<(String, String)>,
    preloads: Option<String>,
    cache_info: Option<WpCacheInfo>,
    data: web::Data<AppData>,
) {
    let prev_cache_info = {
        let mut write_cache = data.cache.write().unwrap();
        let prev_cache_info = write_cache.remove(&url_path).and_then(|c| c.cache_info);
        write_cache.insert(
            url_path.clone(),
            CacheEntry {
                content_type: content_type,
                is_page,
                expire: cache_info.as_ref().and_then(|c| c.date),
                last_modified,
                etag,
                headers,
                path_config,
                preloads,
                data: body,
                cache_info: cache_info.as_ref().map(|c| Box::new(c.clone())),
            },
        );
        prev_cache_info
    };
    // todo: Pass to actor after prioritizing serving request
    // This should maybe also allow just prev_cache_info
    if let Some(cache_info) = cache_info {
        // Add cache dep data
        fn insert_set() -> HashSet<String> {
            HashSet::new()
        }
        {
            // Id set
            if cache_info.cache_ids.len() > 0
                || prev_cache_info
                    .as_ref()
                    .map_or(false, |c| c.cache_ids.len() > 0)
            {
                let diff = prev_cache_info
                    .as_ref()
                    .map(|c| cache_info.cache_ids.difference(&c.cache_ids));
                let mut write_dep_ids = data.cache_dep_id.write().unwrap();
                // Clean up difference (prev - new)
                if let Some(diff) = diff {
                    for id in diff {
                        remove_from_hashmap_set(write_dep_ids.entry(*id), &url_path);
                    }
                }
                for id in &cache_info.cache_ids {
                    let id_set = write_dep_ids.entry(*id).or_insert_with(insert_set);
                    id_set.insert(url_path.clone());
                }
            }
        }
        {
            // Pod set
            if cache_info.pod_types.len() > 0
                || prev_cache_info
                    .as_ref()
                    .map_or(false, |c| c.pod_types.len() > 0)
            {
                let diff = prev_cache_info
                    .as_ref()
                    .map(|c| cache_info.pod_types.difference(&c.pod_types));
                let mut write_dep_pods = data.cache_dep_pod.write().unwrap();
                // Clean up difference (prev - new)
                if let Some(diff) = diff {
                    for pod in diff {
                        remove_from_hashmap_set(write_dep_pods.entry(pod.to_owned()), &url_path);
                    }
                }
                for pod in &cache_info.pod_types {
                    let id_set = write_dep_pods.entry(pod.to_string()).or_insert_with(insert_set);
                    id_set.insert(url_path.clone());
                }
            }
        }
        {
            // Pod change
            if cache_info.pod_change.len() > 0
                || prev_cache_info
                    .as_ref()
                    .map_or(false, |c| c.pod_change.len() > 0)
            {
                let diff = prev_cache_info
                    .as_ref()
                    .map(|c| cache_info.pod_change.difference(&c.pod_change));
                let mut write_dep_pods = data.cache_dep_pod_change.write().unwrap();
                // Clean up difference (prev - new)
                if let Some(diff) = diff {
                    for pod in diff {
                        remove_from_hashmap_set(write_dep_pods.entry(pod.to_owned()), &url_path);
                    }
                }
                for pod in cache_info.pod_change {
                    let id_set = write_dep_pods.entry(pod).or_insert_with(insert_set);
                    id_set.insert(url_path.clone());
                }
            }
        }
        {
            // Timeout
            let prev_date = prev_cache_info.and_then(|c| c.date);
            if cache_info.date.is_some() || prev_date.is_some() {
                let mut write_timeout = data.cache_timeouts.write().unwrap();
                match (prev_date, cache_info.date) {
                    (Some(prev), Some(date)) => {
                        if prev != date {
                            remove_from_btreemap_set(write_timeout.entry(prev), &url_path);
                        }
                        let date_set = write_timeout.entry(date).or_insert_with(insert_set);
                        date_set.insert(url_path);
                    }
                    (Some(prev), None) => {
                        remove_from_btreemap_set(write_timeout.entry(prev), &url_path);
                    }
                    (None, Some(date)) => {
                        let date_set = write_timeout.entry(date).or_insert_with(insert_set);
                        date_set.insert(url_path);
                    }
                    (None, None) => (),
                }
            }
        }
    }
}

// todo: verify if this works for binary data
fn extract_cache_info(
    body: &web::BytesMut,
    replacements: Vec<(String, String)>,
) -> Option<(usize, Result<WpCacheInfo, serde_json::Error>)> {
    if body.ends_with(b"-->") {
        // Search backwards for <!--#cache:
        let start_token = b"<!--#cache:";
        let start_token_len = start_token.len();
        let mut idx = body.len() - b"-->".len() - start_token_len;
        loop {
            if &body[idx..(idx + start_token_len)] == start_token {
                // Found cache data
                let json_slice = &body[idx + start_token_len..body.len() - 3];
                match String::from_utf8(json_slice.to_vec()) {
                    Ok(as_utf8) => {
                        let replaced = replace_urls(as_utf8, replacements, false);
                        let mut cache_info = serde_json::from_str::<WpCacheInfo>(&replaced);
                        // Sort by priority
                        cache_info = cache_info.map(|mut cache_info| {
                            cache_info.preloads.sort_by(|a, b| {
                                let a_priority = match a {
                                    PreloadLink::Style(_, priority) => priority,
                                    PreloadLink::Script(_, priority) => priority,
                                    PreloadLink::Image(_, priority) => priority,
                                    PreloadLink::Font(_, priority) => priority,
                                };
                                let b_priority = match b {
                                    PreloadLink::Style(_, priority) => priority,
                                    PreloadLink::Script(_, priority) => priority,
                                    PreloadLink::Image(_, priority) => priority,
                                    PreloadLink::Font(_, priority) => priority,
                                };
                                a_priority.cmp(b_priority)
                            });
                            cache_info
                        });
                        //println!("{:?}", cache_info);
                        return Some((idx, cache_info));
                    }
                    Err(_) => {
                        return None;
                    }
                }
            }
            if idx == 0 {
                break;
            }
            idx = idx - 1;
        }
        None
    } else {
        None
    }
}

fn map_code_response_body(
    body: web::BytesMut,
    replacements: Vec<(String, String)>,
    replace_escaped: bool,
) -> Result<ResponseBodyData, Error> {
    let (str_body, cache_info) = match extract_cache_info(&body, replacements.clone()) {
        Some((idx, cache_info_res)) => {
            let str_body = match String::from_utf8(body.to_vec()) {
                Ok(str_body) => {
                    // Strip cache data
                    str_body[..idx].to_owned()
                }
                Err(_) => {
                    //println!("{:?}", &body);
                    return Err(Error::from(ProxyError::new("Failed to convert to utf8")));
                }
            };
            (str_body, cache_info_res.ok())
        }
        None => {
            let str_body = match String::from_utf8(body.to_vec()) {
                Ok(str_body) => str_body,
                Err(_) => {
                    //println!("{:?}", &body);
                    return Err(Error::from(ProxyError::new("Failed to convert to utf8")));
                }
            };
            (str_body, None)
        }
    };
    let replaced = replace_urls(str_body, replacements, replace_escaped);
    Ok(ResponseBodyData::StringBody(replaced, cache_info))
}

// todo: Consider consolidating more.
fn map_code_response<'a>(
    resp: actix_web::client::ClientResponse<
        impl Stream<Item = web::Bytes, Error = client::PayloadError> + 'a,
    >,
    content_type: String,
    replacements: Vec<(String, String)>,
    replace_escaped: bool,
) -> impl Future<Item = ResponseData, Error = Error> + 'a {
    // Better would be to parse as stream, so we could
    // also stream output more efficiently
    let resp_headers = resp.headers();
    let last_modified = header_opt(resp_headers, "Last-Modified");
    let whitelist = [
        "Content-Security-Policy"
    ];
    let headers = whitelist.iter()
        .filter_map(|header| header_opt(resp_headers, header).map(|val| (header.to_string(), val)))
        .collect::<Vec<_>>();
    let etag = header_opt(resp_headers, "etag");
    let is_page = is_page(resp_headers);
    resp.from_err()
        .fold(BytesMut::new(), |mut acc, chunk| {
            acc.extend_from_slice(&chunk);
            Ok::<_, Error>(acc)
        })
        .and_then(move |body| {
            map_code_response_body(body, replacements, replace_escaped).map(|body| ResponseData {
                content_type,
                is_page,
                last_modified,
                etag,
                headers,
                body,
            })
        })
}

fn map_binary_body(body: web::BytesMut, replacements: Vec<(String, String)>) -> ResponseBodyData {
    let (body, cache_info) = match extract_cache_info(&body, replacements) {
        Some((idx, cache_info_res)) => (web::Bytes::from(&body[..idx]), cache_info_res.ok()),
        None => (body.freeze(), None),
    };
    ResponseBodyData::BytesBody(body, cache_info)
}

fn map_binary<'a>(
    resp: actix_web::client::ClientResponse<
        impl Stream<Item = web::Bytes, Error = client::PayloadError> + 'a,
    >,
    content_type: String,
    replacements: Vec<(String, String)>,
) -> impl Future<Item = ResponseData, Error = Error> + 'a {
    let headers = resp.headers();
    let last_modified = header_opt(headers, "last_modified");
    let etag = header_opt(headers, "etag");
    let is_page = is_page(headers);
    resp.from_err()
        .fold(BytesMut::new(), |mut acc, chunk| {
            acc.extend_from_slice(&chunk);
            Ok::<_, Error>(acc)
        })
        .map(move |body| ResponseData {
            content_type,
            is_page,
            last_modified,
            etag,
            headers: Vec::new(),
            body: map_binary_body(body, replacements),
        })
}

#[derive(Debug, Clone)]
struct RedirectLoopError;

impl std::fmt::Display for RedirectLoopError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Redirect loop error")
    }
}

impl std::error::Error for RedirectLoopError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl actix_web::ResponseError for RedirectLoopError {}

// Some approximation for own errors, maybe an enum here?
#[derive(Debug, Clone)]
pub struct ProxyError(String);
impl ProxyError {
    pub fn new(msg: impl Into<String>) -> ProxyError {
        ProxyError(msg.into())
    }

    pub fn actix(msg: impl Into<String>) -> Error {
        Error::from(ProxyError(msg.into()))
    }
}
impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Proxy error: {}", &self.0)
    }
}
impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
impl actix_web::ResponseError for ProxyError {}

/// Will follow redirects and return a ClientResponse
fn do_client_request(
    url: String,
    fold_redirects: bool
) -> impl Future<
    Item = awc::ClientResponse<impl Stream<Item = web::Bytes, Error = client::PayloadError>>,
    Error = Error,
> {
    //println!("Request to: {}", &url);
    use future::Loop;
    future::loop_fn((0, url, fold_redirects), |(num, url, fold_redirects)| {
        let client = Client::default();
        client
            .get(url)
            .timeout(std::time::Duration::new(15, 0))
            .header("x-is-proxy", "1")
            .send()
            .map_err(Error::from)
            .and_then(move |resp| {
                //println!("Got response: {}", resp.status().as_u16());
                // todo: Could return an enum Redirect|Response
                let status_code = resp.status().as_u16();
                if fold_redirects && (status_code == 301 || status_code == 307 || status_code == 302) {
                    if num < 5 {
                        let location = header_string(resp.headers(), "Location");
                        //println!("Looped to {}", location);
                        Ok(Loop::Continue((num + 1, location, fold_redirects)))
                    } else {
                        println!("Breaking after 5 redirects");
                        Err(Error::from(RedirectLoopError))
                    }
                } else {
                    //println!("Url: {:?}", &url_path);
                    //println!("Response: {:?}", resp);
                    Ok(Loop::Break(resp))
                }
            })
    })
}

/// Cleans up cache data associated with paths
/// in entries
// Todo: Consider actors or other for this
// At least consider lock potential, maybe common datastructure, break up or same order?
fn clear_cache_entries(entries: Vec<String>, data: web::Data<AppData>) {
    let mut write_cache = data.cache.write().unwrap();
    let mut write_dep_ids = data.cache_dep_id.write().unwrap();
    let mut write_dep_pods = data.cache_dep_pod.write().unwrap();
    let mut write_timeout = data.cache_timeouts.write().unwrap();
    for url_path in &entries {
        // Remove cache entry from and,
        // get registered cache info and clean up
        let prev_cache_info = write_cache.remove(url_path).and_then(|c| c.cache_info);
        if let Some(prev_cache_info) = prev_cache_info {
            // Id set
            for id in prev_cache_info.cache_ids {
                remove_from_hashmap_set(write_dep_ids.entry(id), &url_path);
            }
            // Pod set
            for pod in prev_cache_info.pod_types {
                remove_from_hashmap_set(write_dep_pods.entry(pod.to_owned()), &url_path);
            }
            // Timeout
            if let Some(date) = prev_cache_info.date {
                remove_from_btreemap_set(write_timeout.entry(date), &url_path);
            }
        }
    }
}

/// Reloads and caches entries given by path in `entries`
fn reload_cache_entries(
    entries: Vec<String>,
    data: web::Data<AppData>,
) -> impl Future<Item = (), Error = Error> {
    //println!("Reload {:?}", entries);
    if entries.len() == 0 {
        return Either::A(future::result(Ok(())));
    }
    use future::Loop;
    // Todo: Partition by some number at the time
    Either::B(future::loop_fn(
        (entries, 0 as usize, data),
        |(entries, index, data)| {
            let url_path = &entries[index];
            let cache_data = {
                let read_cache = data.cache.read().unwrap();
                // Try to get required info, return early if no cache entry
                match read_cache.get(url_path) {
                    Some(cache) => {
                        let path_config = cache.path_config.to_owned();
                        let path_config_data = match get_path_config(&data, &path_config) {
                            Ok(p) => p,
                            Err(e) => return Either::A(Either::A(future::err(e))),
                        };
                        let request_url = path_config_data.request_base.to_owned() + "/" + url_path;
                        Some((path_config, request_url, path_config_data.replacements, path_config_data.fold_redirects))
                    }
                    None => None,
                }
            };
            match cache_data {
                Some((path_config, request_url, replacements, fold_redirects)) => Either::A(Either::B(
                    reload_cache_entry(
                        url_path.clone(),
                        path_config,
                        request_url,
                        replacements,
                        fold_redirects,
                        data.clone(),
                    )
                    .and_then(move |_| {
                        if index + 1 < entries.len() {
                            Ok(Loop::Continue((entries, index + 1, data)))
                        } else {
                            Ok(Loop::Break(()))
                        }
                    }),
                )),
                None => Either::B(future::result(Ok(Loop::Continue((
                    entries,
                    index + 1,
                    data,
                ))))),
            }
        },
    ))
}

/// Handling of id change from wp or possibly other backend
pub fn id_changed(
    path: web::Path<(String,u32)>,
    data: web::Data<AppData>,
) -> impl Future<Item = HttpResponse, Error = Error> {
    println!("Id-changed: {}/{}", path.0, path.1);
    // Pod change
    let mut dep_urls = {
        // Well, it's not ok response.. todo
        let read_pod_change = match data.cache_dep_pod_change.read() {
            Ok(r) => r,
            Err(_) => return Either::A(future::ok(HttpResponse::Ok()
                .content_type("text/plain")
                .body(format!("Read access failed"))
            ))
        };
        match read_pod_change.get(&path.0) {
            Some(dep_set) => dep_set.iter().cloned().collect::<HashSet<_>>(),
            None => HashSet::new(),
        }
    };
    {
        let read_cache_dep_id = match data.cache_dep_id.read() {
            Ok(r) => r,
            Err(_) => return Either::A(future::ok(HttpResponse::Ok()
                .content_type("text/plain")
                .body(format!("Read access failed"))
            ))
        };
        match read_cache_dep_id.get(&path.1) {
            Some(dep_set) => dep_urls.extend(dep_set.iter().cloned().collect::<Vec<_>>()),
            None => (),
        }
    }
    // todo: Partition to reload reasonable entries
    clear_cache_entries(vec![], data.clone());
    if dep_urls.len() > 0 {
        Either::B(Either::A(reload_cache_entries(dep_urls.into_iter().collect::<Vec<_>>(), data).and_then(move |_| {
            Ok(HttpResponse::Ok()
                .content_type("text/plain")
                .body(format!("Id changed: {}", path.0)))
        })))
    } else {
        Either::B(Either::B(future::result(Ok(HttpResponse::Ok()
            .content_type("text/plain")
            .body(format!("Id changed: {}", path.0))))))
    }
}

/// Handling of entity added to a type tracked in cache
pub fn pod_added(
    path: web::Path<(String,)>,
    data: web::Data<AppData>,
) -> impl Future<Item = HttpResponse, Error = Error> {
    println!("Pod-added: {}", path.0);
    let dep_urls = {
        let read_cache_dep_pod = data.cache_dep_pod.read().unwrap();
        match read_cache_dep_pod.get(&path.0) {
            Some(dep_set) => dep_set.iter().cloned().collect::<Vec<_>>(),
            None => Vec::new(),
        }
    };
    // todo: Partition to reload reasonable entries
    clear_cache_entries(vec![], data.clone());
    reload_cache_entries(dep_urls, data).and_then(move |_| {
        Ok(HttpResponse::Ok()
            .content_type("text/plain")
            .body(format!("Pod added: {}", path.0)))
    })
}

// Clears cache entries
pub fn clear_cache(data: web::Data<AppData>) -> HttpResponse {
    clear_cache_data(&data);
    HttpResponse::Ok()
        .content_type("text/plain")
        .body(String::from("Cache cleared"))
}

/// Shows status of cache
pub fn cache_status(data: web::Data<AppData>) -> HttpResponse {
    let cache_dep_id = data.cache_dep_id.read().unwrap();
    let cache_dep_pod = data.cache_dep_pod.read().unwrap();
    let static_resolved = data.static_resolved.read().unwrap();
    let response = format!("Dev_mode: {:#?}\nDep_id:\n{:#?}\nDep_pod:\n{:#?}\nStatic resolved:\n{:#?}", data.dev_mode, *cache_dep_id, *cache_dep_pod, *static_resolved);
    HttpResponse::Ok()
        .content_type("text/plain")
        .body(response)
}

pub fn clear_cache_data(data: &web::Data<AppData>) {
    let mut write_cache = data.cache.write().unwrap();
    let mut write_dep_ids = data.cache_dep_id.write().unwrap();
    let mut write_dep_pods = data.cache_dep_pod.write().unwrap();
    let mut write_timeout = data.cache_timeouts.write().unwrap();
    write_cache.clear();
    write_dep_ids.clear();
    write_dep_pods.clear();
    write_timeout.clear();
    let mut static_resolved_write = data.static_resolved.write().unwrap();
    static_resolved_write.clear();
}

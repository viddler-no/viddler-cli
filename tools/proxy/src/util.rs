use actix_web::http::header::{HttpDate, CacheDirective};
use actix_web::{
    http::{
        self,
        header::{self, HeaderMap, HeaderValue},
        StatusCode,
    },
    client,
    web, Error, HttpResponse,
};
use futures::{stream::Stream, Future};
use std::collections::{btree_map, hash_map, HashSet};
use std::fs::File;
use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use crate::ProxyError;

pub fn replace_urls(
    mut str_body: String,
    replacements: Vec<(String, String)>,
    replace_escaped: bool,
) -> String {
    //let start = std::time::Instant::now();
    for (from, to) in replacements {
        str_body = str_body.replace(&from, &to);
        if replace_escaped {
            str_body = str_body.replace(&from.replace("/", "\\/").clone(), &to.replace("/", "\\/"))
        }
    }
    //println!("{:?} {:?}", replaced, start.elapsed().as_millis());
    str_body
}

/// Small helper to read the body stream into bytes
/// Will consume the given response
pub fn body_bytes(
    resp: awc::ClientResponse<impl Stream<Item = web::Bytes, Error = client::PayloadError>>
) -> impl Future<Item = web::BytesMut, Error = Error> {
    resp
        .map_err(Error::from)
        .fold(web::BytesMut::new(), move |mut body, chunk| {
            body.extend_from_slice(&chunk);
            Ok::<_, Error>(body)
        })
}

/// Small helper to read the body stream into a string
/// Will consume the given response
pub fn body_string(
    resp: awc::ClientResponse<impl Stream<Item = web::Bytes, Error = client::PayloadError>>
) -> impl Future<Item = String, Error = Error> {
    resp
        .map_err(Error::from)
        .fold(web::BytesMut::new(), move |mut body, chunk| {
            body.extend_from_slice(&chunk);
            Ok::<_, Error>(body)
        })
        .and_then(|bytes| String::from_utf8(bytes.freeze().to_vec()).map_err(|_| ProxyError::actix("Could not convert bytes to utf-8")))
}

/// Returns (simple, full)
pub fn simple_content_type(headers: &header::HeaderMap) -> (String, String) {
    let content_type = header_string(headers, "content-type");
    // Content-type can be "text/html; charset=UTF-8"
    let content_type_first = match content_type.find(';') {
        Some(idx) => &content_type[0..idx],
        None => &content_type,
    };
    (content_type_first.into(), content_type)
}

pub fn decompressed(
    payload: web::Payload,
    headers: &actix_web::http::header::HeaderMap,
) -> impl Future<Item = web::Bytes, Error = Error> {
    let decompress = actix_web::dev::Decompress::from_headers(payload, headers);
    decompress
        .map_err(Error::from)
        .fold(web::BytesMut::new(), move |mut body, chunk| {
            body.extend_from_slice(&chunk);
            Ok::<_, Error>(body)
        })
        .map(move |body| body.freeze())
}

// From: https://docs.rs/actix-multipart/0.1.2/src/actix_multipart/server.rs.html#84
/// Extract boundary info from headers.
pub fn multipart_boundary(headers: &HeaderMap) -> Result<String, ()> {
    if let Some(content_type) = headers.get(&header::CONTENT_TYPE) {
        if let Ok(content_type) = content_type.to_str() {
            if let Ok(ct) = content_type.parse::<mime::Mime>() {
                if let Some(boundary) = ct.get_param(mime::BOUNDARY) {
                    Ok(boundary.as_str().to_owned())
                } else {
                    Err(())
                }
            } else {
                Err(())
            }
        } else {
            Err(())
        }
    } else {
        Err(())
    }
}

pub fn replace_form_data(
    form_body: &web::Bytes,
    replacements: Vec<(String, String)>,
) -> Result<web::Bytes, serde_urlencoded::ser::Error> {
    let key_values: Result<Vec<(String, String)>, serde_urlencoded::ser::Error> =
        serde_urlencoded::from_bytes::<Vec<(String, String)>>(form_body)
            .map_err(|_| serde_urlencoded::ser::Error::Custom("Decode error".into()));
    //println!("Key values: {:?}", key_values);
    key_values.and_then(|key_values| {
        let key_values = key_values
            .into_iter()
            .map(|(key, value)| (key, replace_urls_rev(value, replacements.clone(), false)))
            .collect::<Vec<(String, String)>>();
        serde_urlencoded::to_string(key_values).map(|string| web::Bytes::from(string.as_bytes()))
    })
}

pub fn replace_in_url(
    url: &str,
    replacements: &Vec<(String, String)>,
) -> String {
    let url = String::from(url);
    let query_split: Vec<&str> = url.split("?").collect();
    if query_split.len() > 1 {
        let scheme_domain = replace_urls(String::from(query_split[0]), replacements.clone(), false);
        let query_hash = String::from(query_split[1]);
        let hash_split: Vec<&str> = query_hash.split("#").collect();
        let (query, hash) = if hash_split.len() > 1 {
            (hash_split[0], Some(hash_split[1]))
        } else {
            (hash_split[0], None)
        };
        // Replace in query key values
        let query_replaced = match serde_urlencoded::from_str::<Vec<(String, String)>>(query) {
            Ok(key_values) => {
                let key_values = key_values
                    .into_iter()
                    .map(|(key, value)| (key, replace_urls(value, replacements.clone(), false)))
                    .collect::<Vec<(String, String)>>();
                let encoded = match serde_urlencoded::to_string(key_values) {
                    Ok(encoded) => encoded,
                    Err(e) => {
                        eprintln!("Failed serialize: {:?}", e);
                        return url;
                    }
                };
                encoded
            }
            Err(e) => {
                eprintln!("Failed deserialize: {:?}", e);
                return url;
            }
        };
        match hash {
            Some(hash) => {
                scheme_domain + "?" + &query_replaced + "#" + hash
            }
            None => {
                scheme_domain + "?" + &query_replaced
            }
        }
    } else {
        // Just replace scheme_domain
        replace_urls(url, replacements.clone(), false)
    }
}

pub fn rev_replacements(replacements: Vec<(String, String)>) -> Vec<(String, String)> {
    replacements.into_iter()
        .map(|(from, to)| (to, from))
        .collect()
}

pub fn replace_urls_rev(
    mut str_body: String,
    replacements: Vec<(String, String)>,
    replace_escaped: bool,
) -> String {
    //let start = std::time::Instant::now();
    for (to, from) in replacements {
        str_body = str_body.replace(&from, &to);
        if replace_escaped {
            str_body = str_body.replace(&from.replace("/", "\\/").clone(), &to.replace("/", "\\/"))
        }
    }
    //println!("{:?} {:?}", replaced, start.elapsed().as_millis());
    str_body
}

pub fn remove_from_hashmap_set<K, V>(entry: hash_map::Entry<K, HashSet<V>>, value: &V)
where
    K: std::cmp::Eq,
    K: std::hash::Hash,
    V: std::cmp::Eq,
    V: std::hash::Hash,
{
    use std::collections::hash_map::Entry;
    match entry {
        Entry::Occupied(mut entry) => {
            let set = entry.get_mut();
            set.remove(value);
            if set.len() == 0 {
                entry.remove();
            }
        }
        Entry::Vacant(_entry) => (),
    }
}
pub fn remove_from_btreemap_set<K, V>(entry: btree_map::Entry<K, HashSet<V>>, value: &V)
where
    K: std::cmp::Eq,
    K: std::hash::Hash,
    K: std::cmp::Ord,
    V: std::cmp::Eq,
    V: std::hash::Hash,
{
    use std::collections::btree_map::Entry;
    match entry {
        Entry::Occupied(mut entry) => {
            let set = entry.get_mut();
            set.remove(value);
            if set.len() == 0 {
                entry.remove();
            }
        }
        Entry::Vacant(_entry) => (),
    }
}

pub fn header_string(headers: &actix_web::http::header::HeaderMap, header: &str) -> String {
    match headers.get(header) {
        Some(header_val) => match header_val.to_str() {
            Ok(str) => str.to_owned(),
            Err(_) => "".to_owned(),
        },
        None => "".to_owned(),
    }
}

pub fn header_opt(headers: &actix_web::http::header::HeaderMap, header: &str) -> Option<String> {
    match headers.get(header) {
        Some(header_val) => match header_val.to_str() {
            Ok(str) => Some(str.to_owned()),
            Err(_) => None,
        },
        None => None,
    }
}

pub fn next_expire(exp_minute_interval: u32) -> Option<(SystemTime, u32)> {
    // todo: Assume chrono would be better, and tz not well handled now
    let now = SystemTime::now();
    if exp_minute_interval == 0 {
        return Some((now, 0));
    }
    let unix_time = now.duration_since(UNIX_EPOCH);
    unix_time.ok().and_then(|unix_time| {
        let max_age = (unix_time.as_secs() as u32) % (60 * exp_minute_interval);
        SystemTime::now().checked_add(Duration::new(
            max_age as u64,
            0,
        )).map(|sys_time| (sys_time, max_age))
    })
}

/// Helper to build response given
/// a cache_file path
pub fn cache_file_response(
    content_type: String,
    last_modified: Option<String>,
    etag: Option<String>,
    headers: Vec<(String, String)>,
    if_none_match: Option<String>,
    preloads: Option<String>,
    status_code: http::StatusCode,
    cache_file: String,
    ranges: Option<HeaderValue>,
    exp_minute_interval: u32,
) -> io::Result<HttpResponse> {
    // Return early if etag and if_none_match matches
    // todo: Disabled because of 304 issues
    if false {
    if let Some(etag) = &etag {
        if let Some(if_none_match) = if_none_match {
            if &if_none_match == etag {
                let mut resp = HttpResponse::NotModified();
                resp.content_type(content_type);
                if let Some(last_modified) = last_modified {
                    resp.header("Last-Modified", last_modified);
                }
                if let Some((next_expire, max_age)) = next_expire(exp_minute_interval) {
                    resp.set(header::Expires(HttpDate::from(next_expire)));
                    resp.set(header::CacheControl(vec![
                        CacheDirective::MaxAge(max_age)
                    ]));
                }
                resp.header("etag", etag.to_owned());
                /*
                for (header, value) in headers {
                    resp.header(&header, value);
                }*/
                if let Some(preloads) = preloads {
                    resp.header("Link", preloads);
                }
                return Ok(resp.finish());
            }
        }
    }}
    let mut resp = HttpResponse::build(status_code);
    resp.content_type(content_type);
    if let Some(last_modified) = last_modified {
        resp.header("Last-Modified", last_modified);
    }
    if let Some((next_expire, max_age)) = next_expire(exp_minute_interval) {
        resp.set(header::Expires(HttpDate::from(next_expire)));
        resp.set(header::CacheControl(vec![
            CacheDirective::MaxAge(max_age)
        ]));
    }
    if let Some(etag) = etag {
        resp.header("etag", etag.to_owned());
    }
    for (header, value) in headers {
        resp.header(&header, value);
    }
    if let Some(preloads) = preloads {
        resp.header("Link", preloads);
    }
    let file = File::open(cache_file)?;
    let metadata = file.metadata()?;
    // Handling byte ranges as done in actix-files
    // https://github.com/actix/actix-web/blob/a3a78ac6fb50c17b73f9d4ac6cac816ceae68bb3/actix-files/src/named.rs#L387
    let length = metadata.len();
    Ok(file_body(resp, ranges, file, length))
}

// Adds file body with handling of byte ranges
pub fn file_body(
    mut resp: actix_web::dev::HttpResponseBuilder,
    ranges: Option<HeaderValue>,
    file: std::fs::File,
    mut length: u64,
) -> HttpResponse {
    resp.header(header::ACCEPT_RANGES, "bytes");
    let mut offset = 0;
    // check for range header
    if let Some(ranges) = ranges {
        if let Ok(rangesheader) = ranges.to_str() {
            if let Ok(rangesvec) = actix_files::HttpRange::parse(rangesheader, length) {
                length = rangesvec[0].length;
                offset = rangesvec[0].start;
                //resp.encoding(ContentEncoding::Identity);
                resp.header(
                    header::CONTENT_RANGE,
                    format!("bytes {}-{}/{}", offset, offset + length - 1, length),
                );
            } else {
                resp.header(header::CONTENT_RANGE, format!("bytes */{}", length));
                return resp.status(StatusCode::RANGE_NOT_SATISFIABLE).finish();
            };
        } else {
            return resp.status(StatusCode::BAD_REQUEST).finish();
        };
    };
    // todo: Possibly not modified here?

    let reader = crate::chunked_file::ChunkedReadFile {
        offset,
        size: length,
        file: Some(file),
        fut: None,
        counter: 0,
    };
    if offset != 0 || length != length {
        return resp.status(StatusCode::PARTIAL_CONTENT).streaming(reader);
    };
    resp.body(actix_web::body::SizedStream::new(length, reader))
}

/// Not modified response used when etag
/// matches If-None-Match from client
pub fn to_not_modified(
    content_type: String,
    last_modified: Option<String>,
    etag: Option<String>,
    preloads: Option<String>,
    exp_minute_interval: u32,
) -> HttpResponse {
    let mut resp = HttpResponse::NotModified();
    resp.content_type(content_type);
    if let Some(last_modified) = last_modified {
        resp.header("Last-Modified", last_modified);
    }
    if let Some((next_expire, max_age)) = next_expire(exp_minute_interval) {
        resp.set(header::Expires(HttpDate::from(next_expire)));
        resp.set(header::CacheControl(vec![
            CacheDirective::MaxAge(max_age)
        ]));
    }
    if let Some(etag) = etag {
        resp.header("etag", etag);
    }
    if let Some(preloads) = preloads {
        resp.header("Link", preloads);
    }
    resp.finish()
}

/// Attempts to extract https domain from a uri, importantly it can
/// fail, and this is used as to also make it work like a check
/// Bit mishmash, but if it's https domain, also checking for www prefix
pub fn uri_to_https_domain(uri: &http::uri::Uri) -> Option<(String, bool)> {
    let scheme = uri.scheme_part().map(|s| s.as_str())?;
    if scheme != "https" {
        return None;
    }
    let host = uri.host()?;
    let parts: Vec<_> = host.split('.').collect();
    // If there are two parts we are happy for now
    // basically distinguishing from ip address
    if parts.len() == 2 {
        Some((host.to_string(), false))
    } else if parts.len() == 3 && parts[0] == "www" {
        Some((format!("{}.{}", parts[1], parts[2]), true))
    } else {
        None
    }
}

pub fn uri_to_string(uri: http::uri::Uri, with_scheme: bool, elide_port_80: bool) -> Result<String, ()> {
    if with_scheme {
        match (
            uri.scheme_part().map(|s| s.as_str()),
            uri.host(),
            uri.port_u16(),
        ) {
            (Some(scheme), Some(host), None) => Ok(String::from(scheme) + "://" + host),
            (Some(scheme), Some(host), Some(port)) => {
                if elide_port_80 && port == 80 {
                    Ok(String::from(scheme) + "://" + host)
                } else {
                    Ok(String::from(scheme) + "://" + host + ":" + &port.to_string())
                }
            }
            _ => Err(()),
        }
    } else {
        match (uri.host(), uri.port_u16()) {
            (Some(host), None) => Ok(String::from(host)),
            (Some(host), Some(port)) => {
                if elide_port_80 && port == 80 {
                    Ok(String::from(host))
                } else {
                    Ok(String::from(host) + ":" + &port.to_string())
                }
            },
            _ => Err(()),
        }
    }
}

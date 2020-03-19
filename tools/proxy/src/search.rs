use actix_web::{
    client::Client,
    web::{self, BytesMut, HttpRequest, HttpResponse},
    Error,
};
//use futures::Stream;
use crate::AppData;
use futures::{stream::Stream, Future, future};
use serde::{Deserialize, Serialize};
use tantivy::{schema, Document, schema::Field};
use crate::proxy::ProxyError;

// Menu data
#[derive(Debug, Deserialize)]
struct AllMenus {
    menus: Vec<MenuEntry>,
}
/// Coming from wordpress menu-admin.php
#[derive(Debug, Deserialize)]
struct MenuEntry {
    location_id: u32,
    location_name: String,
    location_title: String,
    menu: Vec<MenuCategory>,
}
#[derive(Debug, Deserialize)]
struct MenuCategory {
    id: String,
    name: String,
    dishes: Vec<DishEntry>,
}
#[derive(Debug, Deserialize)]
struct DishEntry {
    id: String,
    name: String,
    description: String,
    price: String,
}

/// Holds data related to an index
/// needed in appdata to query and index new
#[derive(Clone)]
struct IndexData {
    index: tantivy::Index,
    reader: tantivy::IndexReader,
}
impl IndexData {
    fn new(index: tantivy::Index, reader: tantivy::IndexReader) -> Self {
        IndexData { index, reader }
    }
}

#[derive(Clone)]
pub struct AllIndexData {
    menu_schema: MenuFields,
    menu_index_data: IndexData,
}

pub fn initial_index_data() -> Result<AllIndexData, String> {
    let menu_schema = menu_schema();
    let menu_index = tantivy::Index::create_in_ram(menu_schema.schema.clone());
    // One reader per index
    let menu_reader = match menu_index.reader() {
        Ok(reader) => reader,
        Err(e) => return Err(format!("Failed getting reader: {:?}", e))
    };
    Ok(AllIndexData {
        menu_schema,
        menu_index_data: IndexData::new(menu_index, menu_reader),
    })
}

#[derive(Deserialize)]
struct SearchQueryParams {
    s: String,
}
#[derive(Serialize)]
struct SearchResult {
    items: Vec<SearchResultItem>,
}
#[derive(Serialize)]
enum SearchResultItem {
    MenuItem {
        dish: String,
        location: String,
        category: String,
        description: String,
        url: String
    },
}

pub fn search_handler(data: web::Data<AppData>, req: HttpRequest) -> HttpResponse {
    let params = match web::Query::<SearchQueryParams>::from_query(&req.query_string()) {
        Ok(params) => params.into_inner(),
        Err(_) => {
            return HttpResponse::Ok().json("Search string `s` required.");
        }
    };
    match data.index_data.as_ref() {
        Some(index_data) => {
            match query_menu_data(index_data, params.s) {
                Ok(result) => HttpResponse::Ok().json(result),
                Err(e) => {
                    eprintln!("Search error: {:?}", e);
                    HttpResponse::InternalServerError().body("Search failed")
                }
            }
        }
        None => HttpResponse::InternalServerError().body("Missing index")
    }
}

/// Attempts to fetch menus, will retry 10 times every 3 seconds
fn fetch_all_menus() -> impl Future<Item = AllMenus, Error = Error> {
    use future::Loop;
    future::loop_fn(0, |tries| {
        let client = Client::default();
        client
            .get("http://wordpress-container/wp-json/brygga/all-menus")
            .timeout(std::time::Duration::new(15, 0))
            .send()
            .map_err(Error::from)
            .then(move |resp| {
                println!("Got resp");
                match resp {
                    Ok(resp) => {
                        Ok(Loop::Break(resp))
                    }
                    Err(e) => {
                        if tries >= 10 {
                            return Err(e);
                        }
                        Ok(Loop::Continue(tries + 1))
                    }
                }
            })
    }).and_then(|resp| {
        println!("Got index response: {}", resp.status().as_u16());
        let status_code = resp.status().as_u16();
        println!("Status code: {}", status_code);
        resp.from_err()
            .fold(BytesMut::new(), |mut acc, chunk| {
                acc.extend_from_slice(&chunk);
                Ok::<_, Error>(acc)
            })
            .and_then(move |body| {
                let body: AllMenus = match serde_json::from_slice(&body) {
                    Ok(body) => body,
                    Err(e) => {
                        return future::err(ProxyError::actix(format!("Menu deserialization failed: {:?}", e)))
                    }
                };
                future::ok(body)
                // One reader per index
            })
    })
}

pub fn index_menus_internal(index_data: AllIndexData) -> impl Future<Item = (), Error = Error> {
    fetch_all_menus()
        .and_then(move |all_menus| {
            match index_menu_data(all_menus, &index_data) {
                Ok(_) => future::ok(()),
                Err(e) => {
                    eprintln!("Could not build search index in internal: {:?}", e);
                    future::err(ProxyError::actix(format!("Could not build search index: {:?}", e)))
                }
            }
        })
}

pub fn index_menus(data: web::Data<AppData>) -> impl Future<Item = HttpResponse, Error = Error> {
    fetch_all_menus()
        .and_then(move |all_menus| {
            let debug = format!("{:?}", all_menus);
            // Should be checked above ideally..
            match data.index_data.as_ref() {
                Some(index_data) => {
                    match index_menu_data(all_menus, index_data) {
                        Ok(_) => {
                            future::ok(HttpResponse::Ok()
                                .content_type("text/plain")
                                .body(debug))
                        }
                        Err(e) => {
                            eprintln!("Could not build search index: {:?}", e);
                            future::ok(HttpResponse::InternalServerError().body("Could not build search index"))
                        }
                    }
                }
                None => future::ok(HttpResponse::InternalServerError().body("Missing index"))
            }
        })
}

fn index_menu_data(all_menus: AllMenus, index_data: &AllIndexData) -> Result<(), String> {
    // This is 10 mb ram
    println!("Indexing menu data");
    let mut index_writer = match index_data.menu_index_data.index.writer(10_000_000) {
        Ok(writer) => writer,
        Err(e) => return Err(format!("Failed getting writer: {:?}", e))
    };
    match index_writer.delete_all_documents() {
        Ok(_) => (),
        Err(e) => return Err(format!("Failed deleting documents: {:?}", e))
    };
    match index_writer.commit() {
        Ok(_) => (),
        Err(e) => return Err(format!("Failed commiting delete documents: {:?}", e))
    };
    for menu in all_menus.menus {
        for category in menu.menu {
            for dish in category.dishes {
                index_writer.add_document(doc!(
                    index_data.menu_schema.location_id => menu.location_id as u64,
                    index_data.menu_schema.location_title => menu.location_title.clone(),
                    index_data.menu_schema.url => format!("/steder/{}/#{}", menu.location_name, dish.id),
                    index_data.menu_schema.category_name => category.name.clone(),
                    index_data.menu_schema.dish_name => dish.name.clone(),
                    index_data.menu_schema.dish_description => dish.description.clone()
                ));
            }
        }
    }
    match index_writer.commit() {
        Ok(_) => Ok(()),
        Err(e) => return Err(format!("Failed commiting new index: {:?}", e))
    }
}

fn doc_field_text(doc: &Document, field: Field) -> String {
    let first = match doc.get_first(field) {
        Some(first) => first,
        None => return String::from("")
    };
    let text = match first.text() {
        Some(text) => text,
        None => return String::from("")
    };
    text.into()
}

fn query_menu_data(index_data: &AllIndexData, query: String) -> Result<SearchResult, String> {
    let searcher = index_data.menu_index_data.reader.searcher();
    let query_parser = tantivy::query::QueryParser::for_index(
        &index_data.menu_index_data.index,
        vec![
            index_data.menu_schema.location_title,
            index_data.menu_schema.category_name,
            index_data.menu_schema.dish_name,
            index_data.menu_schema.dish_description,
        ],
    );
    let query = match query_parser.parse_query(&query) {
        Ok(query) => query,
        Err(e) => return Err(format!("Failed parsing query: {:?}", e))
    };
    //println!("{:?}", query);
    let mut collector = tantivy::collector::TopDocs::with_limit(10);
    let top_docs = match searcher.search(&*query, &mut collector) {
        Ok(top_docs) => top_docs,
        Err(e) => return Err(format!("Failed getting top docs: {:?}", e))
    };
    let items = top_docs
        .into_iter()
        .map(|(_score, doc_address)| {
            let doc = match searcher.doc(doc_address) {
                Ok(doc) => doc,
                Err(e) => return Err(format!("Failed getting doc: {:?}", e))
            };
            let location = doc_field_text(&doc, index_data.menu_schema.location_title);
            let dish = doc_field_text(&doc, index_data.menu_schema.dish_name);
            let category = doc_field_text(&doc, index_data.menu_schema.category_name);
            let description = doc_field_text(&doc, index_data.menu_schema.dish_description);
            let url = doc_field_text(&doc, index_data.menu_schema.url);
            Ok(SearchResultItem::MenuItem {
                location,
                dish,
                category,
                description,
                url
            })
            //println!("{}", index_data.menu_schema.schema.to_json(&doc));
        })
        // http://xion.io/post/code/rust-iter-patterns.html was linked in answer,
        // maybe it could help make this lazy if it isn't or something?
        .collect::<Result<Vec<SearchResultItem>, String>>()?;
    Ok(SearchResult { items })
}

#[derive(Clone)]
pub struct MenuFields {
    location_id: schema::Field,
    location_title: schema::Field,
    category_name: schema::Field,
    dish_name: schema::Field,
    dish_description: schema::Field,
    url: schema::Field,
    schema: schema::Schema,
}

pub fn menu_schema() -> MenuFields {
    use schema::*;
    let mut schema_builder = SchemaBuilder::default();
    // location_id
    let location_id_opts = IntOptions::default().set_stored().set_indexed();
    let location_id = schema_builder.add_u64_field("location_id", location_id_opts);
    // location_title
    let location_title = schema_builder.add_text_field("location_title", TEXT | STORED);
    // category_name
    let category_name = schema_builder.add_text_field("category_name", TEXT | STORED);
    // dish_name
    let dish_name = schema_builder.add_text_field("dish_name", TEXT | STORED);
    // dish_description
    let dish_description = schema_builder.add_text_field("dish_description", TEXT | STORED);
    let url = schema_builder.add_text_field("url", STORED);

    let schema = schema_builder.build();

    MenuFields {
        location_id,
        location_title,
        category_name,
        dish_name,
        dish_description,
        url,
        schema,
    }
}

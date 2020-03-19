// This is forked from the above actix-web-middleware-redirect-https to also support "www." prefix

use actix_service::{Service, Transform};
use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    http, Error, HttpResponse,
};
use futures::{
    future::{ok, Either, FutureResult},
    Poll,
};

#[derive(Default, Clone)]
pub struct RedirMiddleware {
    www: bool,
}

impl RedirMiddleware {
    pub fn new(www: bool) -> Self {
        RedirMiddleware {
            www
        }
    }
}

impl<S, B> Transform<S> for RedirMiddleware
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RedirMiddlewareService<S>;
    type Future = FutureResult<Self::Transform, Self::InitError>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RedirMiddlewareService {
            service,
            www: self.www,
        })
    }
}

pub struct RedirMiddlewareService<S> {
    service: S,
    www: bool,
}

impl<S, B> Service for RedirMiddlewareService<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Either<S::Future, FutureResult<Self::Response, Self::Error>>;

    fn poll_ready(&mut self) -> Poll<(), Self::Error> {
        self.service.poll_ready()
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let redir_host = {
            if self.www {
                let host = req.connection_info().host().to_owned();
                let host_parts: Vec<_> = host.split('.').collect();
                // todo: More robust
                if host_parts.len() == 2 {
                    Some(format!("www.{}.{}", host_parts[0], host_parts[1]))
                } else {
                    // Both localhost and www.example.com should go here
                    None
                }
            } else {
                None
            }
        };
        let redir_url = {
            match redir_host {
                Some(redir_host) => {
                    // Need to redirect anyway, so just add https
                    let path_and_query = match req.uri().path_and_query() {
                        Some(path_and_query) => path_and_query.as_str(),
                        None => ""
                    };
                    println!("Redir_host: {}, path_and_query: {}", redir_host, path_and_query);
                    Some(format!("https://{}{}", redir_host, path_and_query))
                }
                None => {
                    if req.connection_info().scheme() == "https" {
                        None
                    } else {
                        let path_and_query = match req.uri().path_and_query() {
                            Some(path_and_query) => path_and_query.as_str(),
                            None => ""
                        };
                        Some(format!("https://{}{}", req.connection_info().host(), path_and_query))
                    }
                }
            }
        };
        match redir_url {
            Some(redir_url) => {
                Either::B(ok(req.into_response(
                    HttpResponse::MovedPermanently()
                        .header(http::header::LOCATION, redir_url)
                        .finish()
                        .into_body(),
                )))
            }
            None => {
                Either::A(self.service.call(req))
            }
        }
    }
}

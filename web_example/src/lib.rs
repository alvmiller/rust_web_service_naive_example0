use actix_web::dev::ServiceRequest;
use actix_web::{delete, error, get, post, web, HttpResponse, Responder};
use actix_web_httpauth::extractors;
use actix_web_httpauth::extractors::basic::BasicAuth;
use chrono::Utc;
use serde::Serialize;
use tracing::instrument;

use std::sync::Mutex;

pub mod auth;
pub mod db;

pub async fn validator(
    req: ServiceRequest,
    credentials: BasicAuth,
) -> Result<ServiceRequest, (actix_web::Error, ServiceRequest)> {
    let token = credentials.user_id();

    match auth::is_key_allowed_access(token) {
        Ok(true) => Ok(req),
        Ok(false) => Err((
            actix_web::error::ErrorUnauthorized("Supplied token is not authorized."),
            req,
        )),
        Err(_) => Err((actix_web::error::ErrorInternalServerError(""), req)),
    }
}

#[derive(Serialize)]
pub struct SignVal {
    old: f32,
    new: f32,
}

#[derive(Default, Debug)]
pub struct UsageStats {
    pub counters: Mutex<Counters>,
}

#[derive(Default, Debug)]
pub struct Counters {
    change_sign: u32,
}

impl UsageStats {
    pub fn new() -> Self {
        UsageStats::default()
    }
}

#[derive(Serialize)]
struct UsageStatsResponse {
    change_sign: u32,
}

#[get("/change-sign/{ival}")]
#[instrument(skip(stats, database, auth))]
pub async fn change_sign(
    f: web::Path<f32>,
    stats: web::Data<UsageStats>,
    database: web::Data<db::Pool>,
    auth: extractors::basic::BasicAuth,
) -> impl Responder {
    let now = Utc::now();

    actix_web::rt::spawn(async move {
        let mut counters = stats.counters.lock().unwrap();
        counters.change_sign += 1;
    });

    actix_web::rt::spawn(async move {
        let query = db::Query::RecordApiUsage {
            api_key: auth.user_id().to_string(),
            endpoint: db::ApiEndpoint::ChangeSign,
            called_at: now,
        };
        query.execute(database).await
    });

    //async {
    //    let query = db::Query::RecordApiUsage {
    //        api_key: auth.user_id().to_string(),
    //        endpoint: db::ApiEndpoint::ChangeSign,
    //        called_at: now,
    //    };
    //    query.execute(database).await
    //}
    //.await
    //.map_err(error::ErrorInternalServerError)
    //.unwrap();

    let f = f.into_inner();
    let c = 0.0 - f;
    web::Json(SignVal {
        old: f,
        new: c,
    })
}

#[get("/usage-statistics")]
pub async fn usage_statistics(stats: web::Data<UsageStats>) -> impl Responder {
    let mut counters = stats.counters.lock().unwrap();

    let response = UsageStatsResponse {
        change_sign: counters.change_sign,
    };

    counters.change_sign = 0;

    web::Json(response)
}

#[post("/reset-usage-statistics")]
pub async fn reset_usage_statistics(stats: web::Data<UsageStats>) -> impl Responder {
    let mut counters = stats.counters.lock().unwrap();

    counters.change_sign = 0;

    HttpResponse::NoContent()
}

#[get("/api-key")]
#[instrument(skip(database))]
pub async fn request_api_key(database: web::Data<db::Pool>) -> actix_web::Result<impl Responder> {
    let mut api_key = auth::create_api_key();

    let api_key_ = api_key.clone();
    web::block(move || auth::store_api_key(database.clone(), api_key_))
        .await?
        .await?;

    api_key.push_str("\r\n");

    Ok(api_key)
}

#[delete("/api-key")]
pub async fn delete_api_key(
    auth: BasicAuth,
    database: web::Data<db::Pool>,
) -> actix_web::Result<impl Responder> {
    let token = auth.user_id().to_owned();

    web::block(|| auth::revoke_api_key(database, token))
        .await?
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

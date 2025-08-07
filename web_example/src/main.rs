use actix_web::web::scope;
use actix_web::{web, App, HttpServer};
use actix_web_httpauth::middleware::HttpAuthentication;
use log::info;
use r2d2_sqlite::SqliteConnectionManager;
use tracing_actix_web::TracingLogger;
use tracing_subscriber::prelude::*;

use service_actix::{
    db, delete_api_key,
    request_api_key,
    reset_usage_statistics,
    change_sign,
    usage_statistics,
    validator,
    UsageStats,
};

#[actix_web::main]
pub async fn main() -> std::io::Result<()> {
    let log_level: String = std::env::var("LOG").unwrap_or_else(|_| "info".into());
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(log_level))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let manager = SqliteConnectionManager::file(db::DB_FILE);
    let db_pool = db::Pool::new(manager).unwrap();
    db::setup(db_pool.clone());

    let counts = web::Data::new(UsageStats::new());

    HttpServer::new(move || {
        info!("Worker Started...");
        App::new()
            .wrap(TracingLogger::default())
            .app_data(counts.clone())
            .app_data(web::Data::new(db_pool.clone()))
            .service(
                scope("/api")
                    .wrap(HttpAuthentication::basic(validator))
                    .service(change_sign),
            )
            .service(request_api_key)
            .service(delete_api_key)
            .service(usage_statistics)
            .service(reset_usage_statistics)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

use actix_web::{test, web, App};
use actix_web_httpauth::extractors::basic::BasicAuth;
use r2d2_sqlite::SqliteConnectionManager;
use serde_json::json;

use service_actix::{
    auth,
    db,
    delete_api_key,
    request_api_key,
    reset_usage_statistics,
    change_sign,
    usage_statistics,
    UsageStats,
};

#[actix_web::test]
async fn change_sign_endpoint() {
    let db_pool = setup_test_db();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(UsageStats::default()))
            .app_data(web::Data::new(db_pool.clone()))
            .service(change_sign),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/change-sign/42")
        .insert_header(("Authorization", "Basic dGVzdF9rZXk6"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["old"], 42.0);
    assert_eq!(body["new"], -42.0);
}

#[actix_web::test]
async fn usage_statistics_endpoint() {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(UsageStats::default()))
            .service(usage_statistics),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/usage-statistics")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["change_sign"], 0);
}

#[actix_web::test]
async fn reset_usage_statistics_endpoint() {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(UsageStats::default()))
            .service(reset_usage_statistics),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/reset-usage-statistics")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 204);
}

#[actix_web::test]
async fn request_api_key_endpoint() {
    let db_pool = setup_test_db();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(db_pool.clone()))
            .service(request_api_key),
    )
    .await;

    let req = test::TestRequest::get().uri("/api-key").to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    let body = test::read_body(resp).await;
    assert_ne!(body.trim_ascii().len(), 0);
}

#[actix_web::test]
async fn delete_api_key_endpoint() {
    let db_pool = setup_test_db();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(db_pool.clone()))
            .service(delete_api_key),
    )
    .await;

    let req = test::TestRequest::delete()
        .uri("/api-key")
        .insert_header(("Authorization", "Basic dGVzdF9rZXk6"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 204);
}

fn setup_test_db() -> db::Pool {
    let manager = SqliteConnectionManager::memory();
    let pool = db::Pool::new(manager).unwrap();
    db::setup(pool.clone());
    pool
}

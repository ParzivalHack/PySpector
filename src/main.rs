use actix_web::{post, web, App, HttpServer, HttpResponse, Responder};
use actix_governor::{Governor, GovernorConfigBuilder};
use pyo3::prelude::*;

#[post("/analyze")]
async fn analyze_code(_body: String) -> impl Responder {
    let result = Python::with_gil(|py| {
        Ok::<String, PyErr>("PySpector API: Request received".to_string())
    });

    match result {
        Ok(res) => HttpResponse::Ok().body(res),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let gov_conf = GovernorConfigBuilder::default()
        .per_second(12) 
        .burst_size(5)
        .finish()
        .unwrap();

    println!("PySpector API started on port 10000!");

    HttpServer::new(move || {
        App::new()
            .wrap(actix_governor::Governor::new(&gov_conf))
            .service(analyze_code)
    })
    .bind(("0.0.0.0", 10000))?
    .run()
    .await
}
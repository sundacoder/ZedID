mod api;
mod config;
mod state;

use crate::config::AppConfig;
use crate::state::AppState;
use axum::{routing::get_service, Router};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;
use tracing::{info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            "zedid=debug,tower_http=debug,axum=debug".into()
        }))
        .with(tracing_subscriber::fmt::layer().with_target(true))
        .init();

    info!("🛡️  ZedID — Identity Dashboard & Policy Generator");
    info!("   Built with Rust × Tetrate TARS × Zero Trust");
    info!("   Tetrate Buildathon 2025");

    // Load configuration
    let config = AppConfig::load()?;
    info!("Trust domain: {}", config.trust_domain);
    info!("TARS endpoint: {}", config.tars_endpoint);

    // Initialize application state
    let state = AppState::new(config.clone()).await?;

    // Static file directory (dashboard)
    // Static file directory (dashboard)
    // We check multiple locations to handle running from workspace root vs crate root
    let current_dir = std::env::current_dir().unwrap_or_default();
    let candidates = vec![
        current_dir.join("static"),              // If running from zedid-core/
        current_dir.join("zedid-core/static"),   // If running from workspace root
    ];
    
    let static_dir = candidates.into_iter()
        .find(|p| p.exists())
        .unwrap_or_else(|| current_dir.join("static"));

    info!("Serving static files from: {:?}", static_dir);

    let serve_dir = ServeDir::new(&static_dir)
        .not_found_service(ServeFile::new(static_dir.join("index.html")));

    // Build the router
    let app = Router::new()
        // API routes
        .nest("/api/v1", api::router())
        // Serve static dashboard files
        .nest_service("/static", ServeDir::new(&static_dir))
        // Serve index.html at root
        .fallback_service(get_service(serve_dir))
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = format!("0.0.0.0:{}", config.port).parse()?;
    info!("🚀 ZedID API server listening on http://{}", addr);
    info!("📊 Dashboard available at http://localhost:{}", config.port);
    info!("📖 API health at http://localhost:{}/api/v1/health", config.port);
    info!("🤖 System info at http://localhost:{}/api/v1/system/info", config.port);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::config::ServerConfig;

pub async fn create_pool(config: &ServerConfig) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(config.max_db_connections)
        .connect(&config.database_url)
        .await?;
    Ok(pool)
}

pub async fn run_migrations(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!("../../migrations/postgres")
        .run(pool)
        .await?;
    Ok(())
}

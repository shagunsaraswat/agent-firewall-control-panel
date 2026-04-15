#![allow(
    clippy::result_large_err,
    clippy::type_complexity,
    clippy::default_constructed_unit_structs,
    clippy::double_must_use
)]

pub mod app;
pub mod auth;
pub mod config;
pub mod db;
pub mod health;
pub mod idempotency;
pub mod metrics;
pub mod nats;
pub mod proto;
pub mod request_id;
pub mod rest;
pub mod services;

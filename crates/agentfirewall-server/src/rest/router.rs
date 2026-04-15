use axum::Router;

use super::state::AppState;
use super::{approval, incident, learner, policy, run};

pub fn router(state: AppState) -> Router {
    Router::new()
        .nest(
            "/v1",
            Router::new()
                .merge(policy::routes())
                .merge(run::routes())
                .merge(approval::routes())
                .merge(incident::routes())
                .merge(learner::routes()),
        )
        .with_state(state)
}

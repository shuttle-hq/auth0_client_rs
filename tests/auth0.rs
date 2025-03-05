use auth0_client::{users::OperateUsers, Auth0Client};

// Set env vars in .env, then
// RUST_LOG=auth0 cargo test --test auth0 -- --nocapture
#[tokio::test]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    dotenvy::dotenv()?;

    let client = Auth0Client::new(
        &std::env::var("AUTH0_CLIENT_ID").expect("env var required"),
        &std::env::var("AUTH0_CLIENT_SECRET").expect("env var required"),
        &std::env::var("AUTH0_DOMAIN").expect("env var required"),
        &std::env::var("AUTH0_AUDIENCE").expect("env var required"),
    );

    let user = client
        .get_user(&std::env::var("AUTH0_USER_ID").expect("env var required"))
        .await?;

    dbg!(user);

    Ok(())
}

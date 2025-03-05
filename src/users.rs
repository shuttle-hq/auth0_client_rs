//! Types, traits and functions relative to the users API.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error as ThisError;

use crate::error::{Auth0ApiError, Auth0Result, Error};
use crate::Auth0Client;

/// A struct that can interact with the Auth0 users API.
#[async_trait]
pub trait OperateUsers {
    /// Gets a user through the Auth0 users API.
    ///
    /// # Arguments
    /// * `user_id` - The user ID of the user to get.
    ///
    /// # Example
    /// ```
    /// # async fn get_user(mut client: auth0_client::Auth0Client) -> auth0_client::error::Auth0Result<()> {
    /// # use crate::auth0_client::users::OperateUsers;
    /// let user = client.get_user("auth0|63dadcecb564285db4445a75").await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_user(&self, user_id: &str) -> Auth0Result<UserResponse>;

    /// Gets a user through the Auth0 users API.
    ///
    /// # Arguments
    /// * `email` - The email of the user to get.
    /// * `connection` - The connection of the user to get.
    ///
    /// # Example
    /// ```
    /// # async fn get_user(mut client: auth0_client::Auth0Client) -> auth0_client::error::Auth0Result<()> {
    /// # use crate::auth0_client::users::OperateUsers;
    /// let existing = client.get_user_by_email("test@example.com", "Username-Password-Authentication").await?;
    /// let not_existing = client.get_user_by_email("random@example.com", "Username-Password-Authentication").await?;
    ///
    /// assert!(existing.is_some());
    /// assert!(not_existing.is_none());
    /// # Ok(())
    /// # }
    /// ```
    ///
    async fn get_users_by_email(&self, email: &str) -> Auth0Result<Vec<UserResponse>>;

    /// Creates a user through the Auth0 users API.
    ///
    /// # Arguments
    /// * `payload` - A struct containing the necessary information to create a user.
    ///
    /// The `connection` field is mandatory, others depends on the connection type.
    ///
    /// # Example
    /// ```
    /// # async fn create_user(mut client: auth0_client::Auth0Client) -> auth0_client::error::Auth0Result<()> {
    /// # use crate::auth0_client::users::OperateUsers;
    /// let mut payload =
    ///     auth0_client::users::CreateUserPayload::from_connection("Username-Password-Authentication");
    /// payload.email = Some("test@example.com".to_owned());
    /// payload.password = Some("password123456789!".to_owned());
    ///
    /// let new_user = client.create_user(&payload).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn create_user(&self, payload: &CreateUserPayload) -> Auth0Result<UserResponse>;

    /// Updates a user through the Auth0 users API.
    ///
    /// # Arguments
    /// * `user_id` - The user ID of the user to update.
    /// * `payload` - A struct containing the necessary information to update a user.
    ///
    /// # Example
    /// ```
    /// # async fn update_user(mut client: auth0_client::Auth0Client) -> auth0_client::error::Auth0Result<()> {
    /// # use crate::auth0_client::users::OperateUsers;
    /// let mut payload =
    ///     auth0_client::users::UpdateUserPayload::from_connection("Username-Password-Authentication");
    /// payload.password = Some("password123456789!".to_owned());
    ///
    /// let resp = client
    ///     .update_user("auth0|63bfd5cdbd7f2c642dd83768", &payload)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn update_user(
        &self,
        user_id: &str,
        payload: &UpdateUserPayload,
    ) -> Auth0Result<UserResponse>;

    /// Deletes a user through the Auth0 users API.
    ///
    /// # Arguments
    /// * `user_id` - The user ID of the user to delete.
    ///
    /// # Example
    /// ```
    /// # async fn delete_user(mut client: auth0_client::Auth0Client) -> auth0_client::error::Auth0Result<()> {
    /// # use crate::auth0_client::users::OperateUsers;
    ///
    /// let resp = client
    ///     .delete_user("auth0|63bfd5cdbd7f2c642dd83768")
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn delete_user(&self, user_id: &str) -> Auth0Result<()>;
}

/// A struct containing the payload for creating a user.
#[derive(Serialize)]
pub struct CreateUserPayload {
    pub connection: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

/// A struct containing the payload for updating a user.
#[derive(Serialize)]
pub struct UpdateUserPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_email: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_phone_number: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

/// A struct containing the payload for checking a user's password.
#[derive(Default, Serialize)]
pub struct CheckPasswordPayload {
    pub username: String,
    pub password: String,
}

/// A struct containing the response from the Auth0 users API.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserResponse {
    pub user_id: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: String,
    pub nickname: String,
    pub picture: String,
    pub identities: Vec<Identity>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A struct containing an identity of a user.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Identity {
    pub connection: String,
    // NOTE: assumed to be a string, but can be an integer in the case of github connection
    pub user_id: Value,
    pub provider: String,
    #[serde(rename = "isSocial")]
    pub is_social: bool,
}

#[async_trait]
impl OperateUsers for Auth0Client {
    async fn get_user(&self, user_id: &str) -> Auth0Result<UserResponse> {
        self.request::<_, _, UserError>(Method::GET, &format!("/users/{user_id}"), None::<String>)
            .await?
            .ok_or(Error::InvalidResponseBody)
    }

    async fn get_users_by_email(&self, email: &str) -> Auth0Result<Vec<UserResponse>> {
        let res: Vec<UserResponse> = self
            .request::<_, _, UserError>(
                Method::GET,
                &format!(
                    "/users?q=email%3A{}&search_engine=v3",
                    urlencoding::encode(email)
                ),
                None::<String>,
            )
            .await?
            .ok_or(Error::InvalidResponseBody)?;

        Ok(res)
    }

    async fn create_user(&self, payload: &CreateUserPayload) -> Auth0Result<UserResponse> {
        self.request::<_, _, UserError>(Method::POST, "/users", Some(payload))
            .await?
            .ok_or(Error::InvalidResponseBody)
    }

    async fn update_user(
        &self,
        user_id: &str,
        payload: &UpdateUserPayload,
    ) -> Auth0Result<UserResponse> {
        self.request::<_, _, UserError>(Method::PATCH, &format!("/users/{user_id}"), Some(payload))
            .await?
            .ok_or(Error::InvalidResponseBody)
    }

    async fn delete_user(&self, user_id: &str) -> Auth0Result<()> {
        self.request::<_, (), UserError>(
            Method::DELETE,
            &format!("/users/{user_id}"),
            None::<String>,
        )
        .await?;
        Ok(())
    }
}

/// An error representing the possible errors that can occur when interacting with the Auth0 users API.
#[derive(Debug, ThisError)]
pub enum UserError {
    #[error("Invalid request body: {0}")]
    InvalidRequestBody(String),
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Connection not found")]
    ConnectionNotFound,
    #[error("Unknown user error: {0}")]
    Unknown(String),
}

impl From<Auth0ApiError> for UserError {
    fn from(api_error: Auth0ApiError) -> Self {
        match api_error.error_code.as_deref() {
            Some("invalid_body") => Self::InvalidRequestBody(api_error.message),
            Some("auth0_idp_error") => Self::UserAlreadyExists,
            Some("inexistent_connection") => Self::ConnectionNotFound,
            _ => Self::Unknown(api_error.message),
        }
    }
}

impl UpdateUserPayload {
    /// Returns an empty payload for user creation with only `connection` field set.
    ///
    /// # Arguments
    ///
    /// * `connection` - The connection type for the user we want to create.
    pub fn from_connection(connection: &str) -> Self {
        Self {
            connection: Some(connection.to_owned()),
            email: None,
            phone_number: None,
            user_metadata: None,
            blocked: None,
            email_verified: None,
            phone_verified: None,
            app_metadata: None,
            given_name: None,
            family_name: None,
            name: None,
            nickname: None,
            picture: None,
            password: None,
            username: None,
            verify_email: None,
            verify_phone_number: None,
            client_id: None,
        }
    }
}

impl CreateUserPayload {
    /// Returns an empty payload for user update with only `connection` field set.
    ///
    /// # Arguments
    ///
    /// * `connection` - The connection type for the user we want to update.
    pub fn from_connection(connection: &str) -> Self {
        Self {
            connection: connection.to_owned(),
            email: None,
            phone_number: None,
            user_metadata: None,
            blocked: None,
            email_verified: None,
            phone_verified: None,
            app_metadata: None,
            given_name: None,
            family_name: None,
            name: None,
            nickname: None,
            picture: None,
            user_id: None,
            password: None,
            username: None,
        }
    }
}

impl CheckPasswordPayload {
    /// Returns an empty payload for user password checking.
    pub fn new() -> Self {
        Self::default()
    }
}

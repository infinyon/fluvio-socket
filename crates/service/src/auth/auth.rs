use super::error::AuthorizationError;
use async_trait::async_trait;

#[async_trait]
pub trait Authorization<C, I> {
    type Request;
    fn create_authorization_context(identity: I, config: C) -> Self;
    async fn enforce(&self, request: Self::Request) -> Result<bool, AuthorizationError>;
}

#![allow(clippy::assign_op_pattern)]

use std::convert::TryInto;
use std::io::Error as IoError;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::StreamExt;

use fluvio_future::net::TcpStream;
use fluvio_protocol::api::{
    api_decode, ApiMessage, Request, RequestHeader, RequestMessage, ResponseMessage,
};
use fluvio_protocol::bytes::Buf;
use fluvio_protocol::derive::Decode;
use fluvio_protocol::derive::Encode;
use fluvio_socket::FlvSocketError;
use fluvio_socket::InnerFlvSocket;

use tracing::debug;

use crate::api_loop;
use crate::auth::{Authorization, AuthorizationError};
use crate::call_service;
use crate::{FlvService, IdentityContext, SocketBuilder};

#[fluvio(encode_discriminant)]
#[derive(PartialEq, Debug, Encode, Decode, Clone, Copy)]
#[repr(u16)]
pub(crate) enum TestApiRequestEnum {
    Echo = 1000,
    Save = 1001,
}

impl Default for TestApiRequestEnum {
    fn default() -> TestApiRequestEnum {
        TestApiRequestEnum::Echo
    }
}

#[derive(Decode, Encode, Debug, Default)]
pub(crate) struct EchoRequest {
    msg: String,
}

impl EchoRequest {
    pub(crate) fn new(msg: String) -> Self {
        EchoRequest { msg }
    }
}

impl Request for EchoRequest {
    const API_KEY: u16 = TestApiRequestEnum::Echo as u16;
    type Response = EchoResponse;
}

#[derive(Decode, Encode, Default, Debug)]
pub(crate) struct EchoResponse {
    pub msg: String,
}

#[derive(Decode, Encode, Debug, Default)]
pub(crate) struct SaveRequest {}
impl Request for SaveRequest {
    const API_KEY: u16 = TestApiRequestEnum::Save as u16;
    type Response = SaveResponse;
}

#[derive(Decode, Encode, Debug, Default)]
pub(crate) struct SaveResponse {}

#[derive(Debug, Encode)]
pub(crate) enum TestApiRequest {
    EchoRequest(RequestMessage<EchoRequest>),
    SaveRequest(RequestMessage<SaveRequest>),
}

// Added to satisfy Encode/Decode traits
impl Default for TestApiRequest {
    fn default() -> TestApiRequest {
        TestApiRequest::EchoRequest(RequestMessage::default())
    }
}

impl ApiMessage for TestApiRequest {
    type ApiKey = TestApiRequestEnum;

    fn decode_with_header<T>(src: &mut T, header: RequestHeader) -> Result<Self, IoError>
    where
        Self: Default + Sized,
        Self::ApiKey: Sized,
        T: Buf,
    {
        match header.api_key().try_into()? {
            TestApiRequestEnum::Echo => api_decode!(TestApiRequest, EchoRequest, src, header),
            TestApiRequestEnum::Save => api_decode!(TestApiRequest, SaveRequest, src, header),
        }
    }
}

#[derive(Debug)]
pub(crate) struct TestContext {}

impl TestContext {
    pub(crate) fn new() -> Self {
        TestContext {}
    }
}

pub(crate) type SharedTestContext = Arc<TestContext>;

#[derive(Debug)]
pub(crate) struct TestService {}

impl TestService {
    pub fn new() -> TestService {
        Self {}
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TestIdentity {
    role: String,
}

impl TestIdentity {
    pub fn _new(role: String) -> Self {
        TestIdentity { role }
    }

    pub fn _role(&self) -> &str {
        &self.role
    }
}

#[async_trait]
impl IdentityContext for TestIdentity {
    async fn create_from_connection<S>(
        socket: &mut InnerFlvSocket<<S>::Stream>,
    ) -> Result<Self, std::io::Error>
    where
        S: SocketBuilder,
    {
        let identity = {
            let stream = &mut socket.get_mut_stream();

            let mut api_stream = stream.api_stream::<AuthorizationApiRequest, _>();

            if let Some(msg) = api_stream.next().await {
                match msg {
                    Ok(req_msg) => match req_msg {
                        AuthorizationApiRequest::TestAuthRequest(req_msg) => {
                            let principal = req_msg.request.principal;

                            assert_eq!(
                                principal, "admin@infinyon.com",
                                "failed to extract principal, found: {:?}",
                                principal
                            );
                            TestIdentity {
                                role: req_msg.request.role,
                            }
                        }
                    },
                    Err(_e) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "connection closed",
                        ))
                    }
                }
            } else {
                tracing::trace!("client connect terminated");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "connection closed",
                ));
            }
        };

        let sink = &mut socket.get_mut_sink();

        let response = AuthResponse { success: true };

        let msg = ResponseMessage {
            correlation_id: 0,
            response,
        };

        let version = 1;

        if let Ok(()) = sink.send_response(&msg, version).await {
            Ok(identity)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "connection interrupted during response",
            ))
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TestPolicy {}

impl TestPolicy {
    pub fn _new() -> Self {
        TestPolicy {}
    }
}

pub(crate) struct TestAuthorization {
    _identity: TestIdentity,
    _policy: TestPolicy,
}

#[async_trait]
impl Authorization<TestPolicy, TestIdentity> for TestAuthorization {
    type Request = u8;
    fn create_authorization_context(identity: TestIdentity, config: TestPolicy) -> Self {
        TestAuthorization {
            _identity: identity,
            _policy: config,
        }
    }

    async fn enforce(&self, _request: Self::Request) -> Result<bool, AuthorizationError> {
        Ok(true)
    }
}

pub const AUTH_REQUEST_API_KEY: u16 = 8;

// Auth Test Request & Response
#[derive(Decode, Encode, Debug, Default)]
pub struct TestAuthRequest {
    pub principal: String,
    pub role: String,
}

impl TestAuthRequest {
    pub fn new(principal: String, role: String) -> Self {
        TestAuthRequest { principal, role }
    }
}

impl Request for TestAuthRequest {
    const API_KEY: u16 = AUTH_REQUEST_API_KEY;
    type Response = AuthResponse;
}

#[derive(Decode, Encode, Default, Debug)]
pub struct AuthResponse {
    pub success: bool,
}

pub enum AuthorizationApiRequest {
    TestAuthRequest(RequestMessage<TestAuthRequest>),
}

// Added to satisfy Encode/Decode traits
impl Default for AuthorizationApiRequest {
    fn default() -> AuthorizationApiRequest {
        AuthorizationApiRequest::TestAuthRequest(RequestMessage::default())
    }
}

impl ApiMessage for AuthorizationApiRequest {
    type ApiKey = u16;

    fn decode_with_header<T>(src: &mut T, header: RequestHeader) -> Result<Self, std::io::Error>
    where
        Self: Default + Sized,
        Self::ApiKey: Sized,
        T: Buf,
    {
        match header.api_key() {
            AUTH_REQUEST_API_KEY => {
                api_decode!(AuthorizationApiRequest, TestAuthRequest, src, header)
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "api auth header key should be set to {:?}",
                    AUTH_REQUEST_API_KEY
                ),
            )),
        }
    }
}

async fn handle_echo_request(
    msg: RequestMessage<EchoRequest>,
) -> Result<ResponseMessage<EchoResponse>, IoError> {
    let mut response = EchoResponse::default();
    response.msg = msg.request.msg.clone();
    Ok(msg.new_response(response))
}

#[async_trait]
impl FlvService<TcpStream, TestIdentity, TestPolicy> for TestService {
    type Context = SharedTestContext;
    type Request = TestApiRequest;
    type IdentityContext = TestIdentity;
    type Authorization = TestAuthorization;

    async fn respond(
        self: Arc<Self>,
        _context: Self::Context,
        identity: Self::IdentityContext,
        socket: InnerFlvSocket<TcpStream>,
    ) -> Result<(), FlvSocketError> {
        let (mut sink, mut stream) = socket.split();
        let mut api_stream = stream.api_stream::<TestApiRequest, TestApiRequestEnum>();

        // identity context should exist here;
        debug!("Respond with identity context: {:?}", identity);

        api_loop!(
            api_stream,
            TestApiRequest::EchoRequest(request) => call_service!(
                request,
                handle_echo_request(request),
                sink,
                "echo request handler"
            ),
            TestApiRequest::SaveRequest(_request) =>  {
                drop(api_stream);
                //let _orig_socket: FlvSocket  = (sink,stream).into();
                break;
            }
        );

        Ok(())
    }
}

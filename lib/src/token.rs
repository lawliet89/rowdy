use std::io::Cursor;
use std::time::Duration;

use chrono::{DateTime, UTC};
use jwt;
use rocket::http::{ContentType, Status};
use rocket::response::{Response, Responder};
use serde::{Serialize, Deserialize};
use serde_json;

#[derive(Default, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct PrivateClaim {}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Token<T: Serialize + Deserialize> {
    pub token: jwt::ClaimsSet<T>,
    #[serde(with = "::serde_custom::duration")]
    pub expires_in: Duration,
    pub issued_at: DateTime<UTC>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>, // TODO
}

impl<'r, T: Serialize + Deserialize> Responder<'r> for Token<T> {
    fn respond(self) -> Result<Response<'r>, Status> {
        let serialized = serde_json::to_string(&self).map_err(|e| {
                         error_!("Error serializing Token: {:?}", e);
                         Status::InternalServerError
                     })?;

        Response::build().header(ContentType::JSON).sized_body(Cursor::new(serialized)).ok()
    }
}

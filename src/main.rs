#![warn(rust_2018_idioms)]

use std::env;
use std::str;

use base64;
use base64::encode;
use bytes::Bytes;
use hyper;
use hyper::{Client, Method, Request};
use hyper::body::HttpBody;
use hyper_tls::HttpsConnector;
use rusoto_core;
use rusoto_core::{Region, RusotoError};
use rusoto_kms;
use rusoto_kms::{DecryptError, DecryptRequest, DecryptResponse, Kms, KmsClient};
use serde_derive::Deserialize;
use serde_json::json;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Cli {
    start_year: i32,
    end_year: i32,
}

#[derive(Deserialize, Debug, Default)]
struct MovieYear {
    #[serde(default)]
    columns: Vec<String>,
    #[serde(default)]
    data: Vec<Vec<String>>,
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() -> Result<()> {
    let url = env::var("URL")?;
    let user = env::var("NEO4J_USER")?;
    let password = env::var("NEO4J_PASSWORD")?;
    let kms_key_id = env::var("KMS_KEY_ID")?;

    let kms_client = KmsClient::new(Region::UsEast1);

    let user = String::from_utf8(decrypt(user, &kms_client, &kms_key_id)
        .await?
        .plaintext.unwrap()
        .to_vec())?;

    let password = String::from_utf8(decrypt(password, &kms_client, &kms_key_id)
        .await?
        .plaintext.unwrap()
        .to_vec())?;

    let args: Cli = Cli::from_args();
    let request = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header("content-type", "application/json")
        .header("Authorization", format!("Basic {}", encode(format!("{}:{}", user, password))))
        .body(json!({
                    "query": "MATCH (r:Movie) WHERE r.released >= {start} AND r.released < {end} RETURN r.title",
                    "params": { "start": args.start_year, "end": args.end_year, }
                    }).to_string().into())?;

    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    let mut response = client.request(request).await?;

    assert_eq!(response.status(), 200);

    let mut buffer = String::new();

    while let Some(chunk) = response.body_mut().data().await {
        buffer.push_str(str::from_utf8(&chunk?)?);
    }

    let v: MovieYear = serde_json::from_str(&buffer)?;

    for movie in v.data {
        println!("{:?}", movie[0]);
    }

    Ok(())
}

async fn decrypt<T: AsRef<[u8]>>(input: T, kms_client: &KmsClient, kms_key_id: &String)
    -> std::result::Result<DecryptResponse, RusotoError<DecryptError>> {
    let request = DecryptRequest {
        ciphertext_blob: Bytes::from(base64::decode(input).unwrap()),
        encryption_algorithm: Some(String::from("SYMMETRIC_DEFAULT")),
        encryption_context: None,
        grant_tokens: None,
        key_id: Some(String::from(kms_key_id)),
    };

    kms_client.decrypt(request).await
}

use axum::{
    body::Body,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, head, put},
    Router,
};
use clap::Parser;
use hmac::{Hmac, KeyInit, Mac}; 
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc};
use tokio::{fs, io::AsyncWriteExt};
use tower_http::cors::CorsLayer;
use tracing::{info, warn};


type HmacSha256 = Hmac<Sha256>;

#[derive(Parser)]
#[command(name = "simple-s3-server")]
struct Args {
    #[arg(long, default_value = "0.0.0.0", env = "HOST")]
    host: String,

    #[arg(short, long, default_value = "9000", env = "PORT")]
    port: u16,

    #[arg(short, long, default_value = "simple-bucket", env = "BUCKET")]
    bucket: String,

    #[arg(long, default_value = "mykey", env = "ACCESS_KEY")]
    access_key: String,

    #[arg(long, default_value = "mysecret", env = "SECRET_KEY")]
    secret_key: String,

    #[arg(short, long, default_value = "./s3-data", env = "DATA_DIR")]
    data_dir: PathBuf,
}
#[derive(Clone)]
struct AppState {
    bucket_name: String,
    access_key: String,
    secret_key: String,
    data_dir: PathBuf,
}

#[derive(Debug, Deserialize)]
struct ListObjectsQuery {
    #[serde(rename = "max-keys")]
    max_keys: Option<usize>,
    prefix: Option<String>,
    marker: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename = "ListBucketResult")]
struct ListBucketResult {
    #[serde(rename = "@xmlns")]
    xmlns: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Prefix")]
    prefix: String,
    #[serde(rename = "Marker")]
    marker: String,
    #[serde(rename = "MaxKeys")]
    max_keys: usize,
    #[serde(rename = "IsTruncated")]
    is_truncated: bool,
    #[serde(rename = "Contents")]
    contents: Vec<ObjectInfo>,
}

#[derive(Debug, Serialize)]
struct ObjectInfo {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "LastModified")]
    last_modified: String,
    #[serde(rename = "ETag")]
    etag: String,
    #[serde(rename = "Size")]
    size: u64,
    #[serde(rename = "StorageClass")]
    storage_class: String,
}


fn verify_aws_v4_signature(
    auth_header: &str,
    headers: &HeaderMap,
    method: &Method,
    uri_path: &str,
    query: &str,
    state: &AppState,
) -> bool {
    let content_sha256 = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("UNSIGNED-PAYLOAD");

    let amz_date = headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");


    let mut credential = "";
    let mut signed_headers = "";
    let mut signature = "";

    let auth_parts = auth_header
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .unwrap_or("");

    for part in auth_parts.split(", ") {
        if let Some(cred) = part.strip_prefix("Credential=") {
            credential = cred;
        } else if let Some(headers_part) = part.strip_prefix("SignedHeaders=") {
            signed_headers = headers_part;
        } else if let Some(sig) = part.strip_prefix("Signature=") {
            signature = sig;
        }
    }


    let cred_parts: Vec<&str> = credential.split('/').collect();
    if cred_parts.len() != 5 {
        return false;
    }
    let access_key = cred_parts[0];
    let date = cred_parts[1];
    let region = cred_parts[2];
    let service = cred_parts[3];

    if access_key != state.access_key {
        warn!("Mismatched access key in V4 auth");
        return false;
    }

    let mut canonical_headers = String::new();
    let mut sorted_signed_headers: Vec<&str> =
        signed_headers.split(';').collect();
    sorted_signed_headers.sort_unstable();

    for header_name in &sorted_signed_headers {
        if let Some(value) = headers.get(*header_name) {
            canonical_headers
                .push_str(&format!("{}:{}\n", header_name, value.to_str().unwrap_or("").trim()));
        }
    }

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method,
        uri_path,
        query,
        canonical_headers,
        signed_headers,
        content_sha256
    );

    let canonical_request_hash =
        hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let scope = format!("{}/{}/{}/{}/aws4_request", date, region, service, "aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, scope, canonical_request_hash
    );

    let secret = format!("AWS4{}", state.secret_key);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(date.as_bytes());
    let date_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&date_key).unwrap();
    mac.update(region.as_bytes());
    let region_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&region_key).unwrap();
    mac.update(service.as_bytes());
    let service_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&service_key).unwrap();
    mac.update(b"aws4_request");
    let signing_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&signing_key).unwrap();
    mac.update(string_to_sign.as_bytes());
    let calculated_signature = hex::encode(mac.finalize().into_bytes());

    info!("Provided Signature:   {}", signature);
    info!("Calculated Signature: {}", calculated_signature);


    calculated_signature == signature
}

fn verify_auth(
    headers: &HeaderMap,
    query: &str,
    method: &Method,
    uri_path: &str,
    state: &AppState,
) -> bool {
    if let (Some(access_header), Some(secret_header)) = (
        headers.get("x-amz-access-key"),
        headers.get("x-amz-secret-key"),
    ) {
        if let (Ok(access_str), Ok(secret_str)) =
            (access_header.to_str(), secret_header.to_str())
        {
            info!("✓ Using custom headers auth");
            return access_str == state.access_key && secret_str == state.secret_key;
        }
    }

    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            let auth_clean = auth_str.strip_prefix("Bearer ").unwrap_or(auth_str);

            if let Some((access, secret)) = auth_clean.split_once(':') {
                info!("✓ Using simple auth header");
                return access == state.access_key && secret == state.secret_key;
            }
        }
    }

    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("AWS4-HMAC-SHA256") {
                info!("🔐 Verifying AWS v4 signature...");
                return verify_aws_v4_signature(
                    auth_str, headers, method, uri_path, query, state,
                );
            }
        }
    }

    if !query.is_empty() {
        for param in query.split('&') {
            if let Some((key, value)) = param.split_once('=') {
                if key == "access_key" && value == state.access_key {
                    for param2 in query.split('&') {
                        if let Some((key2, value2)) = param2.split_once('=') {
                            if key2 == "secret_key" && value2 == state.secret_key {
                                info!("✓ Using query param auth");
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    warn!("❌ No valid authentication found");
    false
}

// Auth middleware
async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = request.headers().clone();
    let query = request.uri().query().unwrap_or("").to_string();
    let method = request.method().clone();
    let uri_path = request.uri().path().to_string();

    if verify_auth(&headers, &query, &method, &uri_path, &state) {
        Ok(next.run(request).await)
    } else {
        warn!("🚫 Unauthorized request");
        Err(StatusCode::UNAUTHORIZED)
    }
}

// List objects in bucket
async fn list_objects(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListObjectsQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    let max_keys = params.max_keys.unwrap_or(1000).min(1000);
    let prefix = params.prefix.unwrap_or_default();

    let mut objects = Vec::new();

    if let Ok(mut entries) = fs::read_dir(&state.data_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Ok(metadata) = entry.metadata().await {
                if metadata.is_file() {
                    let file_name =
                        entry.file_name().to_string_lossy().to_string();

                    if file_name.starts_with(&prefix) {
                        let size = metadata.len();

                        let modified = metadata
                            .modified()
                            .unwrap_or(std::time::SystemTime::now());

                        let datetime: chrono::DateTime<chrono::Utc> =
                            modified.into();
                        let last_modified = datetime
                            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                            .to_string();

                        let etag = format!(
                            "\"{}\"",
                            hex::encode(Sha256::digest(format!(
                                "{}:{}",
                                file_name, size
                            )))
                        );

                        objects.push(ObjectInfo {
                            key: file_name,
                            last_modified,
                            etag,
                            size,
                            storage_class: "STANDARD".to_string(),
                        });

                        if objects.len() >= max_keys {
                            break;
                        }
                    }
                }
            }
        }
    }

    objects.sort_by(|a, b| a.key.cmp(&b.key));

    let result = ListBucketResult {
        xmlns: "http://s3.amazonaws.com/doc/2006-03-01/".to_string(),
        name: state.bucket_name.clone(),
        prefix,
        marker: params.marker.unwrap_or_default(),
        max_keys,
        is_truncated: false,
        contents: objects,
    };

    let xml = serde_xml_rs::to_string(&result)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/xml"),
    );
    headers.insert("server", HeaderValue::from_static("SimpleS3/1.0"));

    Ok((headers, xml))
}

// Get object
async fn get_object(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let file_path = state.data_dir.join(&key);

    match fs::read(&file_path).await {
        Ok(data) => {
            let mut headers = HeaderMap::new();

            let mime_type =
                mime_guess::from_path(&file_path).first_or_octet_stream();
            headers.insert(
                "content-type",
                HeaderValue::from_str(mime_type.as_ref()).unwrap(),
            );

            let etag = format!("\"{}\"", hex::encode(Sha256::digest(&data)));
            headers.insert("etag", HeaderValue::from_str(&etag).unwrap());
            headers.insert(
                "content-length",
                HeaderValue::from_str(&data.len().to_string()).unwrap(),
            );
            headers
                .insert("accept-ranges", HeaderValue::from_static("bytes"));

            Ok((headers, data))
        }
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

// Put object
async fn put_object(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    body: Body,
) -> Result<impl IntoResponse, StatusCode> {
    let file_path = state.data_dir.join(&key);

    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut file = fs::File::create(&file_path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    file.write_all(&bytes)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let etag = format!("\"{}\"", hex::encode(Sha256::digest(&bytes)));

    let mut headers = HeaderMap::new();
    headers.insert("etag", HeaderValue::from_str(&etag).unwrap());

    info!("📁 Stored object: {} ({} bytes)", key, bytes.len());

    Ok((StatusCode::OK, headers))
}

// Delete object
async fn delete_object(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let file_path = state.data_dir.join(&key);

    match fs::remove_file(&file_path).await {
        Ok(_) => {
            info!("🗑️ Deleted object: {}", key);
            Ok(StatusCode::NO_CONTENT)
        }
        Err(_) => Ok(StatusCode::NO_CONTENT),
    }
}

// Head object
async fn head_object(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let file_path = state.data_dir.join(&key);

    match fs::metadata(&file_path).await {
        Ok(metadata) => {
            let mut headers = HeaderMap::new();

            let mime_type =
                mime_guess::from_path(&file_path).first_or_octet_stream();
            headers.insert(
                "content-type",
                HeaderValue::from_str(mime_type.as_ref()).unwrap(),
            );
            headers.insert(
                "content-length",
                HeaderValue::from_str(&metadata.len().to_string()).unwrap(),
            );

            let etag = format!(
                "\"{}\"",
                hex::encode(Sha256::digest(format!(
                    "{}:{}",
                    key,
                    metadata.len()
                )))
            );
            headers.insert("etag", HeaderValue::from_str(&etag).unwrap());

            Ok((StatusCode::OK, headers))
        }
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    fs::create_dir_all(&args.data_dir).await?;

    let state = Arc::new(AppState {
        bucket_name: args.bucket.clone(),
        access_key: args.access_key.clone(),
        secret_key: args.secret_key.clone(),
        data_dir: args.data_dir.clone(),
    });

    let app = Router::new()
        .route("/", get(list_objects))
        .route("/{*key}", get(get_object))
        .route("/{*key}", put(put_object))
        .route("/{*key}", delete(delete_object))
        .route("/{*key}", head(head_object))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = format!("{}:{}", args.host, args.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    info!("🚀 S3-compatible server starting on http://{}", addr);
    info!("📦 Bucket: {}", args.bucket);
    info!("💾 Data directory: {}", args.data_dir.display());

    axum::serve(listener, app).await?;

    Ok(())
}
//! Thin SigV4 adapter over the same HTTPS socket and verified shipper driver.
use super::{client::Client, config::ShippingConfig};
use gateway_core::{calendar, s3, shipper::{Path, Reply, Request}};

fn text(bytes: Vec<u8>) -> Option<String> { String::from_utf8(bytes).ok() }

pub(super) fn send(config: &ShippingConfig, client: Option<&Client>, request: Request, now_ms: u64) -> Reply {
    // Activation is local: no AWS secret is ever passed through HypAware enrollment.
    if request.path != Path::Ingest { return s3::activation(); }
    let failed = || s3::upload_reply(0, None);
    let (Some(aws), Some(client), Some(batch)) = (&config.s3, client, request.batch_id.as_deref()) else { return failed(); };
    if batch.len() > 1024 || request.body.len() > 4 * 1024 * 1024 { return failed(); }
    let Some(path) = text(s3::object_path(aws.prefix.as_bytes(), batch, &request.body)) else { return failed(); };
    let civil = calendar::civil(now_ms);
    if civil.year > 9999 { return failed(); }
    let date = format!("{:04}{:02}{:02}T{:02}{:02}{:02}Z", civil.year, civil.month, civil.day, civil.hour, civil.minute, civil.second);
    let signed = s3::sign(config.server.authority().as_bytes(), path.as_bytes(), date.as_bytes(), aws.region.as_bytes(),
        aws.access_key.as_bytes(), config.token(), aws.session_token.as_bytes(), &request.body);
    let (Some(auth), Some(hash)) = (text(signed.authorization), text(signed.payload_hash)) else { return failed(); };
    let mut headers = vec![("authorization", auth), ("x-amz-content-sha256", hash), ("x-amz-date", date),
        ("content-type", "application/x-ndjson".to_owned())];
    if !aws.session_token.is_empty() { headers.push(("x-amz-security-token", aws.session_token.clone())); }
    match client.request("PUT", &path, None, &headers, request.body) {
        Ok(reply) => s3::upload_reply(reply.status, reply.retry_after),
        Err(_) => failed(),
    }
}

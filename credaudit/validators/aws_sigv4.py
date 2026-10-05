"""Minimal AWS Signature Version 4 signer.

This exists for exactly one call: `sts:GetCallerIdentity`, AWS's own
read-only "which credential am I" endpoint -- the identical call every
AWS SDK (boto3 included) makes internally whenever *it* needs to
confirm a credential works. Implementing SigV4 here avoids adding a
multi-megabyte `boto3`/`botocore` dependency for a single GET request.

This is an authentication mechanism, not an attack technique: SigV4 is
AWS's public, documented request-signing scheme
(https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html),
required to make *any* authenticated call to *any* AWS API, including
completely benign ones. Nothing here enumerates permissions, lists
resources, or touches any service other than STS's identity check.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret_access_key: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _sign(("AWS4" + secret_access_key).encode("utf-8"), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    return _sign(k_service, "aws4_request")


def build_get_caller_identity_request(access_key_id: str, secret_access_key: str, region: str = "us-east-1") -> dict:
    """Return {"url": ..., "headers": ...} for a signed, ready-to-send
    GET request to STS's GetCallerIdentity action. Pure request
    construction -- does not perform any network I/O itself, so it's
    independently unit-testable without mocking `requests`."""
    service = "sts"
    host = "sts.amazonaws.com" if region == "us-east-1" else f"sts.{region}.amazonaws.com"
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    canonical_uri = "/"
    canonical_querystring = "Action=GetCallerIdentity&Version=2011-06-15"
    canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-date"
    payload_hash = hashlib.sha256(b"").hexdigest()
    canonical_request = "\n".join(
        ["GET", canonical_uri, canonical_querystring, canonical_headers, signed_headers, payload_hash]
    )

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [algorithm, amz_date, credential_scope, hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()]
    )

    signing_key = _signing_key(secret_access_key, date_stamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization_header = (
        f"{algorithm} Credential={access_key_id}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    return {
        "url": f"https://{host}/?{canonical_querystring}",
        "headers": {"x-amz-date": amz_date, "Authorization": authorization_header, "Host": host},
    }

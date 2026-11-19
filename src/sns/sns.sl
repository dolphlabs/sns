// Amazon SNS: publish (one or a batch) to a topic, manage topics and
// subscriptions, and verify the notifications SNS delivers to an HTTP(S)
// endpoint. Signed with the stdlib's sigv4; works against AWS and
// LocalStack.
//
//     import "sns";
//
//     let r = sns.from_env(proc.getenv);
//     guard let c = r else let e = err_of(r) { panic(e); }
//     sns.publish(c, topic_arn, "{\"order\":42}", deadline);
//
//     // in the handler SNS posts to:
//     let v = sns.new_verifier();
//     let nr = sns.verify(v, body, deadline);   // result[Notification, str]

import "crypto";
import "httpc";
import "sigv4";
import "strings";
import "time";
import "x509";

pub gc struct Client {
    endpoint: str,
    host: str,
    signer: sigv4.Signer,
    http: httpc.Client,
}

pub fn new_client(endpoint: str, region: str, access_key: str, secret_key: str)
                  -> result[Client, str] {
    let u = strings.trim(endpoint);
    while strings.has_suffix(u, "/") {
        u = strings.slice(u, 0, len(u) - 1);
    }
    let rest = "";
    if strings.has_prefix(u, "https://") {
        rest = strings.slice(u, 8, len(u));
    } else if strings.has_prefix(u, "http://") {
        rest = strings.slice(u, 7, len(u));
    } else {
        return err("sns: endpoint must start with https:// or http://");
    }
    if rest == "" || strings.contains(rest, "/") || strings.contains(rest, "?") {
        return err("sns: endpoint is scheme://host[:port] with no path");
    }
    if region == "" {
        return err("sns: region is required");
    }
    if access_key == "" || secret_key == "" {
        return err("sns: access key and secret key are required");
    }
    let host = rest;
    if strings.has_prefix(u, "https://") && strings.has_suffix(host, ":443") {
        host = strings.slice(host, 0, len(host) - 4);
    } else if strings.has_prefix(u, "http://") && strings.has_suffix(host, ":80") {
        host = strings.slice(host, 0, len(host) - 3);
    }
    let scheme = strings.slice(u, 0, strings.find(u, "://"));
    return ok(Client { endpoint: scheme + "://" + host, host: host,
                       signer: sigv4.new_signer(access_key, secret_key, region, "sns"),
                       http: httpc.new_client() });
}

// AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN (optional),
// AWS_REGION (or AWS_DEFAULT_REGION), and SNS_ENDPOINT (default: the
// region's AWS endpoint).
pub fn from_env(getenv: fn(str) -> opt[str]) -> result[Client, str] {
    let region = getenv("AWS_REGION") ?? (getenv("AWS_DEFAULT_REGION") ?? "");
    if region == "" {
        return err("sns: AWS_REGION is not set");
    }
    let endpoint = getenv("SNS_ENDPOINT") ?? ("https://sns." + region + ".amazonaws.com");
    let r = new_client(endpoint, region, getenv("AWS_ACCESS_KEY_ID") ?? "",
                       getenv("AWS_SECRET_ACCESS_KEY") ?? "");
    guard let c = r else let e = err_of(r) { return err(e); }
    c.signer.session_token = getenv("AWS_SESSION_TOKEN") ?? "";
    return ok(c);
}

fn call(c: Client, params: map[str]str, deadline: until) -> result[str, str] {
    let payload = to_bytes(form(params));
    let h: map[str]str = {};
    h["content-type"] = "application/x-www-form-urlencoded; charset=utf-8";
    let amzdate = sigv4.amz_date_now();
    let auth = sigv4.sign(c.signer, "POST", c.host, "/", {}, h, sigv4.payload_hash(payload), amzdate);
    let req = httpc.new_request("POST", c.endpoint + "/");
    req.headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8";
    req.headers["X-Amz-Date"] = amzdate;
    if c.signer.session_token != "" {
        req.headers["X-Amz-Security-Token"] = c.signer.session_token;
    }
    req.headers["Authorization"] = auth;
    req.body = payload;
    req.max_redirects = 0;
    let rr = httpc.client_send(c.http, req, deadline);
    guard let resp = rr else let e = err_of(rr) { return err("sns: " + params["Action"] + ": " + e); }
    let text = to_str(resp.body);
    if resp.status < 200 || resp.status > 299 {
        return err(error_text(resp.status, text));
    }
    return ok(text);
}

// ---- publishing ---------------------------------------------------------------------

pub fn publish(c: Client, topic_arn: str, message: str, deadline: until) -> result[Published, str] {
    return publish_message(c, topic_arn, outgoing(message), deadline);
}

pub fn publish_message(c: Client, topic_arn: str, m: Outgoing, deadline: until)
                       -> result[Published, str] {
    let p = check_outgoing(m);
    if len(p) > 0 {
        return err("sns: " + p);
    }
    let r = call(c, publish_params(topic_arn, m), deadline);
    guard let body = r else let e = err_of(r) { return err(e); }
    let id = xml_text(body, "MessageId");
    if len(id) == 0 {
        return err("sns: Publish reply without a MessageId");
    }
    return ok(Published { id: id, sequence: xml_text(body, "SequenceNumber") });
}

// Up to 10 messages; err only when the call failed, each entry's outcome
// in its BatchResult, in the order given.
pub fn publish_batch(c: Client, topic_arn: str, ms: [Outgoing], deadline: until)
                     -> result[[BatchResult], str] {
    if len(ms) == 0 || len(ms) > max_batch() {
        return err("sns: a batch holds 1 to 10 messages");
    }
    let problems: [str] = [];
    for i in 0..len(ms) {
        let p = check_outgoing(ms[i]);
        if len(p) > 0 {
            push(problems, "message " + to_str(i) + ": " + p);
        }
    }
    if len(problems) > 0 {
        return err("sns: " + strings.join(problems, "; "));
    }
    let r = call(c, publish_batch_params(topic_arn, ms), deadline);
    guard let body = r else let e = err_of(r) { return err(e); }
    return decode_batch(body, len(ms));
}

// ---- topics and subscriptions -------------------------------------------------------

// The topic's ARN; an existing topic of that name gives its ARN.
// Attributes by SNS's names: FifoTopic, ContentBasedDeduplication,
// SignatureVersion, ...
pub fn create_topic(c: Client, name: str, attributes: map[str]str, deadline: until)
                    -> result[str, str] {
    let p = base_params("CreateTopic");
    p["Name"] = name;
    let i = 1;
    for k, v in attributes {
        p["Attributes.entry." + to_str(i) + ".key"] = k;
        p["Attributes.entry." + to_str(i) + ".value"] = v;
        i += 1;
    }
    let r = call(c, p, deadline);
    guard let body = r else let e = err_of(r) { return err(e); }
    let arn = xml_text(body, "TopicArn");
    if len(arn) == 0 {
        return err("sns: CreateTopic reply without a TopicArn");
    }
    return ok(arn);
}

pub fn delete_topic(c: Client, topic_arn: str, deadline: until) -> result[bool, str] {
    let p = base_params("DeleteTopic");
    p["TopicArn"] = topic_arn;
    let r = call(c, p, deadline);
    guard let _b = r else let e = err_of(r) { return err(e); }
    return ok(true);
}

pub fn set_topic_attribute(c: Client, topic_arn: str, name: str, value: str, deadline: until)
                           -> result[bool, str] {
    let p = base_params("SetTopicAttributes");
    p["TopicArn"] = topic_arn;
    p["AttributeName"] = name;
    p["AttributeValue"] = value;
    let r = call(c, p, deadline);
    guard let _b = r else let e = err_of(r) { return err(e); }
    return ok(true);
}

// protocol: "https", "sqs", "email", "lambda", ...; endpoint: the URL,
// queue ARN or address. The subscription's ARN, or "pending
// confirmation" until an HTTP(S) or email subscriber confirms.
pub fn subscribe(c: Client, topic_arn: str, protocol: str, endpoint: str, deadline: until)
                 -> result[str, str] {
    let p = base_params("Subscribe");
    p["TopicArn"] = topic_arn;
    p["Protocol"] = protocol;
    p["Endpoint"] = endpoint;
    p["ReturnSubscriptionArn"] = "true";
    let r = call(c, p, deadline);
    guard let body = r else let e = err_of(r) { return err(e); }
    return ok(xml_text(body, "SubscriptionArn"));
}

pub fn unsubscribe(c: Client, subscription_arn: str, deadline: until) -> result[bool, str] {
    let p = base_params("Unsubscribe");
    p["SubscriptionArn"] = subscription_arn;
    let r = call(c, p, deadline);
    guard let _b = r else let e = err_of(r) { return err(e); }
    return ok(true);
}

// ---- verifying notifications --------------------------------------------------------

// Verifies notifications, fetching each signing certificate once.
pub gc struct Verifier {
    http: httpc.Client,
    lock: mutex,
    certs: map[str]str,
    // Seconds a notification's Timestamp may be in the past; 0 for no
    // limit. Defends against replays of an old, validly signed message.
    max_age: int,
}

pub fn new_verifier() -> Verifier {
    let m: map[str]str = {};
    return Verifier { http: httpc.new_client(), lock: make_mutex(), certs: m, max_age: 3600 };
}

// The notification checked against the certificate's public key: the
// signature (SignatureVersion 2), the certificate's validity now, and
// the message's age. cert_pem is the leaf SNS signs with.
pub fn verify_with_cert(n: Notification, cert_pem: str, now_unix: int, max_age: int)
                        -> result[bool, str] {
    let sr = decode_signature(n);
    guard let sig = sr else let e = err_of(sr) { return err(e); }
    let cr = x509.parse_pem(cert_pem);
    guard let certs = cr else let e = err_of(cr) { return err("sns: signing certificate: " + e); }
    if len(certs) == 0 {
        return err("sns: the signing certificate URL held no certificate");
    }
    let leaf = certs[0];
    if leaf.key_type != "rsa" {
        return err("sns: the signing certificate's key is " + leaf.key_type + ", not RSA");
    }
    if !x509.valid_at(leaf, now_unix) {
        return err("sns: the signing certificate is not valid now");
    }
    let nr = crypto.rsa_public_n(leaf.public_key_pem);
    guard let rn = nr else let e = err_of(nr) { return err("sns: signing key: " + e); }
    let er = crypto.rsa_public_e(leaf.public_key_pem);
    guard let re = er else let e = err_of(er) { return err("sns: signing key: " + e); }
    let vr = crypto.rsa_verify_sha256(rn, re, to_bytes(string_to_sign(n)), sig);
    guard let good = vr else let e = err_of(vr) { return err("sns: " + e); }
    if !good {
        return err("sns: the signature does not match the notification");
    }
    return check_age(n.timestamp, now_unix, max_age);
}

// A notification sent more than max_age seconds before now (0: no limit)
// is a replay of an old, validly signed message.
pub fn check_age(timestamp: str, now_unix: int, max_age: int) -> result[bool, str] {
    if max_age <= 0 {
        return ok(true);
    }
    let tr = timestamp_unix(timestamp);
    guard let at = tr else let e = err_of(tr) { return err(e); }
    if now_unix - at > max_age {
        return err("sns: the notification is " + to_str(now_unix - at) + " s old, over " + to_str(max_age));
    }
    return ok(true);
}

// "2026-11-19T21:50:23.123Z" to unix seconds.
fn timestamp_unix(ts: str) -> result[int, str] {
    if len(ts) < 20 || strings.slice(ts, 10, 11) != "T" || !strings.has_suffix(ts, "Z") {
        return err("sns: a Timestamp that is not RFC 3339 UTC");
    }
    let y = to_int(strings.slice(ts, 0, 4)) ?? -1;
    let mo = to_int(strings.slice(ts, 5, 7)) ?? -1;
    let d = to_int(strings.slice(ts, 8, 10)) ?? -1;
    let h = to_int(strings.slice(ts, 11, 13)) ?? -1;
    let mi = to_int(strings.slice(ts, 14, 16)) ?? -1;
    let s = to_int(strings.slice(ts, 17, 19)) ?? -1;
    if y < 1970 || mo < 1 || mo > 12 || d < 1 || d > 31 || h < 0 || h > 23 || mi < 0 || mi > 59 || s < 0 || s > 60 {
        return err("sns: a Timestamp that is not RFC 3339 UTC");
    }
    // days from civil (Howard Hinnant's algorithm)
    let yy = y;
    if mo <= 2 {
        yy -= 1;
    }
    let era = yy / 400;
    let yoe = yy - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    return ok(days * 86400 + h * 3600 + mi * 60 + s);
}

fn cert_for(v: Verifier, url: str, deadline: until) -> result[str, str] {
    mutex_lock(v.lock);
    if has(v.certs, url) {
        let pem = v.certs[url];
        mutex_unlock(v.lock);
        return ok(pem);
    }
    mutex_unlock(v.lock);
    let req = httpc.new_request("GET", url);
    req.max_redirects = 0;
    let rr = httpc.client_send(v.http, req, deadline);
    guard let resp = rr else let e = err_of(rr) { return err("sns: fetching the signing certificate: " + e); }
    if resp.status != 200 || len(resp.body) > 65536 {
        return err("sns: fetching the signing certificate: HTTP " + to_str(resp.status));
    }
    let pem = to_str(resp.body);
    mutex_lock(v.lock);
    // A bounded cache: SNS rotates certificates rarely, so a full map
    // means someone is cycling URLs; start over rather than grow.
    if len(v.certs) >= 64 {
        let fresh: map[str]str = {};
        v.certs = fresh;
    }
    v.certs[url] = pem;
    mutex_unlock(v.lock);
    return ok(pem);
}

// A notification body checked end to end: an SNS certificate URL, the
// certificate fetched over verified TLS (and cached), the signature, and
// the age. A confirmation's SubscribeURL is checked to be an SNS URL
// too, so confirming it cannot be turned into a request elsewhere.
pub fn verify(v: Verifier, body: str, deadline: until) -> result[Notification, str] {
    let pr = parse_notification(body);
    guard let n = pr else let e = err_of(pr) { return err(e); }
    let ur = check_cert_url(n.signing_cert_url);
    guard let _u = ur else let e = err_of(ur) { return err(e); }
    if n.kind != "Notification" {
        let sr = check_sns_url(n.subscribe_url);
        guard let _s = sr else let e = err_of(sr) { return err(e); }
    }
    let cr = cert_for(v, n.signing_cert_url, deadline);
    guard let pem = cr else let e = err_of(cr) { return err(e); }
    let now = (time.wall() as int) / 1000000000;
    let vr = verify_with_cert(n, pem, now, v.max_age);
    guard let _ok = vr else let e = err_of(vr) { return err(e); }
    return ok(n);
}

// Confirms an HTTP(S) subscription by fetching its verified SubscribeURL.
pub fn confirm(v: Verifier, n: Notification, deadline: until) -> result[bool, str] {
    if n.kind != "SubscriptionConfirmation" {
        return err("sns: only a SubscriptionConfirmation can be confirmed");
    }
    let sr = check_sns_url(n.subscribe_url);
    guard let _s = sr else let e = err_of(sr) { return err(e); }
    let req = httpc.new_request("GET", n.subscribe_url);
    req.max_redirects = 0;
    let rr = httpc.client_send(v.http, req, deadline);
    guard let resp = rr else let e = err_of(rr) { return err("sns: confirming: " + e); }
    if resp.status != 200 {
        return err(error_text(resp.status, to_str(resp.body)));
    }
    return ok(true);
}

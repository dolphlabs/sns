// SNS's Query protocol and notification format as pure functions: form
// bodies built from checked values, XML replies read, and the string an
// SNS notification's signature covers. No network and no clock.

import "builder";
import "encoding";
import "json";
import "sigv4";
import "strings";

pub gc struct Outgoing {
    message: str,
    // Email subscribers' subject line; at most 100 printable ASCII characters.
    subject: str,
    // String message attributes, used by subscription filter policies.
    attributes: map[str]str,
    // FIFO topics: required group id, and a deduplication id unless the
    // topic derives it from the message.
    group_id: str,
    dedup_id: str,
}

pub fn outgoing(message: str) -> Outgoing {
    let a: map[str]str = {};
    return Outgoing { message: message, subject: "", attributes: a, group_id: "", dedup_id: "" };
}

pub struct Published { id: str, sequence: str }

pub gc struct BatchResult { index: int, ok: bool, id: str, error: str }

pub fn max_batch() -> int { return 10; }

// Every problem with one message, joined; "" when it can be sent.
pub fn check_outgoing(m: Outgoing) -> str {
    let ps: [str] = [];
    if len(m.message) == 0 {
        push(ps, "a message cannot be empty");
    }
    if len(m.subject) > 100 {
        push(ps, "a subject is at most 100 characters");
    }
    for c in to_bytes(m.subject) {
        let v = c as int;
        if v < 32 || v > 126 {
            push(ps, "a subject is printable ASCII on one line");
            break;
        }
    }
    if len(m.attributes) > 10 {
        push(ps, "a message has at most 10 attributes");
    }
    for k, _v in m.attributes {
        if len(k) == 0 || len(k) > 256 || strings.has_prefix(strings.to_lower(k), "aws.") ||
            strings.has_prefix(strings.to_lower(k), "amazon.") {
            push(ps, "attribute " + json.encode(k) + ": names are 1 to 256 characters, not starting with AWS. or Amazon.");
        }
    }
    if len(m.group_id) > 128 || len(m.dedup_id) > 128 {
        push(ps, "group_id and dedup_id are at most 128 characters");
    }
    return strings.join(ps, "; ");
}

// application/x-www-form-urlencoded, in sorted order, with SigV4's
// encoding (which form decoding reads the same).
pub fn form(params: map[str]str) -> str {
    return sigv4.canonical_query(params);
}

fn entry_params(p: map[str]str, prefix: str, m: Outgoing) {
    p[prefix + "Message"] = m.message;
    if len(m.subject) > 0 {
        p[prefix + "Subject"] = m.subject;
    }
    if len(m.group_id) > 0 {
        p[prefix + "MessageGroupId"] = m.group_id;
    }
    if len(m.dedup_id) > 0 {
        p[prefix + "MessageDeduplicationId"] = m.dedup_id;
    }
    let i = 1;
    for k, v in m.attributes {
        let e = prefix + "MessageAttributes.entry." + to_str(i) + ".";
        p[e + "Name"] = k;
        p[e + "Value.DataType"] = "String";
        p[e + "Value.StringValue"] = v;
        i += 1;
    }
}

pub fn base_params(action: str) -> map[str]str {
    let p: map[str]str = {};
    p["Action"] = action;
    p["Version"] = "2010-03-31";
    return p;
}

pub fn publish_params(topic_arn: str, m: Outgoing) -> map[str]str {
    let p = base_params("Publish");
    p["TopicArn"] = topic_arn;
    entry_params(p, "", m);
    return p;
}

pub fn publish_batch_params(topic_arn: str, ms: [Outgoing]) -> map[str]str {
    let p = base_params("PublishBatch");
    p["TopicArn"] = topic_arn;
    for i in 0..len(ms) {
        let pre = "PublishBatchRequestEntries.member." + to_str(i + 1) + ".";
        p[pre + "Id"] = to_str(i);
        entry_params(p, pre, ms[i]);
    }
    return p;
}

// ---- reading XML replies ------------------------------------------------------------
//
// SNS's replies are flat, known documents; these read the few elements
// used without a general XML parser.

pub fn xml_text(x: str, tag: str) -> str {
    let open = "<" + tag + ">";
    let at = strings.find(x, open);
    if at < 0 {
        return "";
    }
    let rest = strings.slice(x, at + len(open), len(x));
    let end = strings.find(rest, "</" + tag + ">");
    if end < 0 {
        return "";
    }
    return xml_unescape(strings.slice(rest, 0, end));
}

pub fn xml_blocks(x: str, tag: str) -> [str] {
    let out: [str] = [];
    let open = "<" + tag + ">";
    let close = "</" + tag + ">";
    let rest = x;
    while true {
        let at = strings.find(rest, open);
        if at < 0 {
            break;
        }
        rest = strings.slice(rest, at + len(open), len(rest));
        let end = strings.find(rest, close);
        if end < 0 {
            break;
        }
        push(out, strings.slice(rest, 0, end));
        rest = strings.slice(rest, end + len(close), len(rest));
    }
    return out;
}

fn xml_unescape(s: str) -> str {
    if !strings.contains(s, "&") {
        return s;
    }
    return strings.replace(strings.replace(strings.replace(strings.replace(strings.replace(s,
        "&lt;", "<"), "&gt;", ">"), "&quot;", "\""), "&apos;", "'"), "&amp;", "&");
}

// "sns: NotFound: Topic does not exist" from an ErrorResponse.
pub fn error_text(status: int, body: str) -> str {
    let code = xml_text(body, "Code");
    if len(code) == 0 {
        return "sns: HTTP " + to_str(status);
    }
    let msg = xml_text(body, "Message");
    if len(msg) == 0 {
        return "sns: " + code;
    }
    return "sns: " + code + ": " + msg;
}

pub fn decode_batch(body: str, n: int) -> result[[BatchResult], str] {
    let out: [BatchResult] = [];
    for i in 0..n {
        push(out, BatchResult { index: i, ok: false, id: "", error: "sns: no result for this entry" });
    }
    let ok_part = xml_text_raw(body, "Successful");
    for m in xml_blocks(ok_part, "member") {
        let ir = to_int(xml_text(m, "Id"));
        guard let i = ir else { return err("sns: batch reply names an unknown entry"); }
        if i < 0 || i >= n {
            return err("sns: batch reply names an unknown entry");
        }
        out[i] = BatchResult { index: i, ok: true, id: xml_text(m, "MessageId"), error: "" };
    }
    let bad_part = xml_text_raw(body, "Failed");
    for m in xml_blocks(bad_part, "member") {
        let ir = to_int(xml_text(m, "Id"));
        guard let i = ir else { return err("sns: batch reply names an unknown entry"); }
        if i < 0 || i >= n {
            return err("sns: batch reply names an unknown entry");
        }
        let text = "sns: " + xml_text(m, "Code");
        let msg = xml_text(m, "Message");
        if len(msg) > 0 {
            text = text + ": " + msg;
        }
        out[i] = BatchResult { index: i, ok: false, id: "", error: text };
    }
    return ok(out);
}

// The element's content, not unescaped (it holds more elements).
fn xml_text_raw(x: str, tag: str) -> str {
    let blocks = xml_blocks(x, tag);
    if len(blocks) == 0 {
        return "";
    }
    return blocks[0];
}

// ---- notifications ------------------------------------------------------------------

// A message SNS delivered to an HTTP(S) endpoint, as its JSON body holds it.
pub gc struct Notification {
    // "Notification", "SubscriptionConfirmation" or "UnsubscribeConfirmation".
    kind: str,
    id: str,
    topic_arn: str,
    subject: str,
    message: str,
    // RFC 3339, when SNS sent it.
    timestamp: str,
    // Confirmations: the URL to GET to confirm, and its token.
    subscribe_url: str,
    token: str,
    signature_version: str,
    signature: str,
    signing_cert_url: str,
}

gc struct WireNote {
    Type: str,
    MessageId: str,
    TopicArn: str,
    Subject: opt[str],
    Message: str,
    Timestamp: str,
    SubscribeURL: opt[str],
    Token: opt[str],
    SignatureVersion: str,
    Signature: str,
    SigningCertURL: str,
}

pub fn parse_notification(body: str) -> result[Notification, str] {
    if len(body) > 1048576 {
        return err("sns: a notification body over 1 MiB");
    }
    let r: result[WireNote, str] = json.decode(body);
    guard let w = r else let e = err_of(r) { return err("sns: not an SNS notification: " + e); }
    if w.Type != "Notification" && w.Type != "SubscriptionConfirmation" && w.Type != "UnsubscribeConfirmation" {
        return err("sns: unknown notification type " + json.encode(w.Type));
    }
    return ok(Notification {
        kind: w.Type, id: w.MessageId, topic_arn: w.TopicArn, subject: w.Subject ?? "",
        message: w.Message, timestamp: w.Timestamp, subscribe_url: w.SubscribeURL ?? "",
        token: w.Token ?? "", signature_version: w.SignatureVersion, signature: w.Signature,
        signing_cert_url: w.SigningCertURL
    });
}

// What the signature covers: name/value lines in this fixed order, the
// subject only when present (AWS, "Verifying the signatures of Amazon SNS
// messages").
pub fn string_to_sign(n: Notification) -> str {
    let b = builder.new_str();
    b.write("Message\n" + n.message + "\n");
    b.write("MessageId\n" + n.id + "\n");
    if n.kind == "Notification" {
        if len(n.subject) > 0 {
            b.write("Subject\n" + n.subject + "\n");
        }
    } else {
        b.write("SubscribeURL\n" + n.subscribe_url + "\n");
    }
    b.write("Timestamp\n" + n.timestamp + "\n");
    if n.kind != "Notification" {
        b.write("Token\n" + n.token + "\n");
    }
    b.write("TopicArn\n" + n.topic_arn + "\n");
    b.write("Type\n" + n.kind + "\n");
    return b.finish();
}

fn host_of(url: str) -> str {
    let rest = strings.slice(url, 8, len(url));
    let slash = strings.find(rest, "/");
    if slash < 0 {
        return rest;
    }
    return strings.slice(rest, 0, slash);
}

// sns.<region>.amazonaws.com (or .com.cn), over https, a .pem path: any
// other URL is a certificate an attacker chose.
pub fn check_sns_url(url: str) -> result[bool, str] {
    if !strings.has_prefix(url, "https://") || strings.contains(url, "?") || strings.contains(url, "#") ||
        strings.contains(url, "@") {
        return err("sns: the URL is not a plain https:// URL");
    }
    let host = host_of(url);
    let region = "";
    if strings.has_prefix(host, "sns.") && strings.has_suffix(host, ".amazonaws.com") {
        region = strings.slice(host, 4, len(host) - 14);
    } else if strings.has_prefix(host, "sns.") && strings.has_suffix(host, ".amazonaws.com.cn") {
        region = strings.slice(host, 4, len(host) - 17);
    } else {
        return err("sns: " + host + " is not an SNS host");
    }
    if len(region) == 0 {
        return err("sns: " + host + " names no region");
    }
    for c in to_bytes(region) {
        let v = c as int;
        if !((v >= 97 && v <= 122) || (v >= 48 && v <= 57) || v == 45) {
            return err("sns: " + host + " is not an SNS host");
        }
    }
    return ok(true);
}

pub fn check_cert_url(url: str) -> result[bool, str] {
    let r = check_sns_url(url);
    guard let _ok = r else let e = err_of(r) { return err(e); }
    if !strings.has_suffix(url, ".pem") {
        return err("sns: the signing certificate URL does not name a .pem file");
    }
    return ok(true);
}

pub fn decode_signature(n: Notification) -> result[bytes, str] {
    if n.signature_version != "2" {
        return err("sns: SignatureVersion " + n.signature_version +
                   " (SHA-1) is not accepted; set the topic's SignatureVersion attribute to 2");
    }
    let r = encoding.base64_decode(n.signature);
    guard let sig = r else { return err("sns: the signature is not base64"); }
    return ok(sig);
}

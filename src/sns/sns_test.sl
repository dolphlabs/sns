import "crypto";
import "encoding";
import "json";
import "strings";
import "x509";

fn test_publish_params_and_form() {
    let m = outgoing("hello & bye");
    m.subject = "Hi";
    m.attributes["kind"] = "order";
    let f = form(publish_params("arn:aws:sns:eu-west-1:1:t", m));
    assert(f == "Action=Publish&Message=hello%20%26%20bye&MessageAttributes.entry.1.Name=kind&" +
           "MessageAttributes.entry.1.Value.DataType=String&MessageAttributes.entry.1.Value.StringValue=order&" +
           "Subject=Hi&TopicArn=arn%3Aaws%3Asns%3Aeu-west-1%3A1%3At&Version=2010-03-31", f);
    let b = form(publish_batch_params("t", [outgoing("a"), outgoing("b")]));
    assert(strings.contains(b, "PublishBatchRequestEntries.member.1.Id=0&PublishBatchRequestEntries.member.1.Message=a&" +
           "PublishBatchRequestEntries.member.2.Id=1&PublishBatchRequestEntries.member.2.Message=b"), b);
}

fn test_checks() {
    assert(check_outgoing(outgoing("x")) == "");
    let m = outgoing("");
    m.subject = "line\nbreak";
    m.attributes["AWS.x"] = "v";
    let p = check_outgoing(m);
    assert(strings.contains(p, "empty") && strings.contains(p, "one line") && strings.contains(p, "AWS."), p);
}

fn test_replies_and_errors() {
    let ok_reply = "<PublishResponse><PublishResult><MessageId>m-1</MessageId></PublishResult></PublishResponse>";
    assert(xml_text(ok_reply, "MessageId") == "m-1");
    assert(error_text(404, "<ErrorResponse><Error><Type>Sender</Type><Code>NotFound</Code><Message>Topic does not exist</Message></Error></ErrorResponse>") ==
           "sns: NotFound: Topic does not exist");
    assert(error_text(500, "oops") == "sns: HTTP 500");
    let batch = "<PublishBatchResponse><PublishBatchResult><Successful><member><Id>1</Id><MessageId>m</MessageId></member></Successful>" +
        "<Failed><member><Id>0</Id><Code>InvalidParameter</Code><Message>too long &amp; bad</Message><SenderFault>true</SenderFault></member></Failed>" +
        "</PublishBatchResult></PublishBatchResponse>";
    let r = decode_batch(batch, 2);
    guard let rs = r else let e = err_of(r) { panic(e); }
    assert(!rs[0].ok && rs[0].error == "sns: InvalidParameter: too long & bad", rs[0].error);
    assert(rs[1].ok && rs[1].id == "m");
}

fn test_urls() {
    assert(check_cert_url("https://sns.eu-west-1.amazonaws.com/SimpleNotificationService-abc.pem") ?? false);
    assert(check_cert_url("https://sns.cn-north-1.amazonaws.com.cn/x.pem") ?? false);
    for bad in ["http://sns.us-east-1.amazonaws.com/x.pem", "https://sns.us-east-1.amazonaws.com.evil.com/x.pem",
                "https://evil.com/sns.us-east-1.amazonaws.com/x.pem", "https://sns..amazonaws.com/x.pem",
                "https://sns.us-east-1.amazonaws.com/x.txt", "https://u@sns.us-east-1.amazonaws.com/x.pem",
                "https://sns.us_east.amazonaws.com/x.pem", "https://xsns.us-east-1.amazonaws.com/x.pem"] {
        assert(!(check_cert_url(bad) ?? false), bad);
    }
}

fn note(kind: str) -> Notification {
    return Notification {
        kind: kind, id: "id-1", topic_arn: "arn:aws:sns:us-east-1:1:t", subject: "", message: "hello",
        timestamp: "2026-11-19T12:00:00.000Z", subscribe_url: "https://sns.us-east-1.amazonaws.com/c",
        token: "tok", signature_version: "2", signature: "",
        signing_cert_url: "https://sns.us-east-1.amazonaws.com/x.pem"
    };
}

fn test_string_to_sign() {
    let n = note("Notification");
    assert(string_to_sign(n) == "Message\nhello\nMessageId\nid-1\nTimestamp\n2026-11-19T12:00:00.000Z\n" +
           "TopicArn\narn:aws:sns:us-east-1:1:t\nType\nNotification\n", string_to_sign(n));
    n.subject = "S";
    assert(strings.contains(string_to_sign(n), "MessageId\nid-1\nSubject\nS\nTimestamp"));
    let c = note("SubscriptionConfirmation");
    assert(string_to_sign(c) == "Message\nhello\nMessageId\nid-1\nSubscribeURL\nhttps://sns.us-east-1.amazonaws.com/c\n" +
           "Timestamp\n2026-11-19T12:00:00.000Z\nToken\ntok\nTopicArn\narn:aws:sns:us-east-1:1:t\nType\nSubscriptionConfirmation\n");
}

fn test_parse_notification() {
    let body = "{\"Type\":\"Notification\",\"MessageId\":\"id-1\",\"TopicArn\":\"t\",\"Message\":\"m\"," +
        "\"Timestamp\":\"2026-11-19T12:00:00.000Z\",\"SignatureVersion\":\"2\",\"Signature\":\"AA==\"," +
        "\"SigningCertURL\":\"https://sns.us-east-1.amazonaws.com/x.pem\",\"UnsubscribeURL\":\"u\"}";
    let r = parse_notification(body);
    guard let n = r else let e = err_of(r) { panic(e); }
    assert(n.kind == "Notification" && n.subject == "" && n.message == "m");
    let bad = parse_notification(strings.replace(body, "\"Notification\"", "\"Other\""));
    guard let _b = bad else { return; }
    panic("an unknown type was accepted");
}

fn test_timestamps() {
    assert((timestamp_unix("1970-01-01T00:00:00.000Z") ?? -1) == 0);
    assert((timestamp_unix("2026-11-19T12:00:00.000Z") ?? -1) == 1795089600, to_str(timestamp_unix("2026-11-19T12:00:00.000Z") ?? -1));
    assert((timestamp_unix("2000-03-01T00:00:00Z") ?? -1) == 951868800);
    assert(!((timestamp_unix("2026-11-19 12:00:00Z") ?? -1) >= 0));
}

// A key and certificate of our own stand in for SNS's.
fn signed(kind: str, key: str) -> Notification {
    let n = note(kind);
    let sr = crypto.rsa_sign_sha256(key, to_bytes(string_to_sign(n)));
    guard let sig = sr else let e = err_of(sr) { panic(e); }
    n.signature = encoding.base64_encode(sig);
    return n;
}

fn test_verify_with_cert() {
    let kr = crypto.rsa_generate(2048);
    guard let key = kr else let e = err_of(kr) { panic(e); }
    let cr = x509.self_signed(key, x509.Request { common_name: "sns.amazonaws.com", dns_names: ["sns.amazonaws.com"], ip_addrs: [] }, 30);
    guard let cert = cr else let e = err_of(cr) { panic(e); }
    let certs = x509.parse_pem(cert) ?? [];
    let in_window = certs[0].not_before + 60;
    let n = signed("Notification", key);
    assert(verify_with_cert(n, cert, in_window, 0) ?? false);
    assert(verify_with_cert(signed("SubscriptionConfirmation", key), cert, in_window, 0) ?? false);
    // Any change to a signed field breaks it.
    n.message = "hellO";
    assert(strings.contains(err_text(verify_with_cert(n, cert, in_window, 0)), "does not match"));
    // Version 1 (SHA-1) is refused, whatever the signature.
    let v1 = signed("Notification", key);
    v1.signature_version = "1";
    assert(strings.contains(err_text(verify_with_cert(v1, cert, in_window, 0)), "SignatureVersion 1"));
    // Outside the certificate's validity.
    assert(strings.contains(err_text(verify_with_cert(signed("Notification", key), cert, certs[0].not_after + 1, 0)), "not valid now"));
    // Another key's signature.
    let other = crypto.rsa_generate(2048) ?? "";
    assert(strings.contains(err_text(verify_with_cert(signed("Notification", other), cert, in_window, 0)), "does not match"));
}

fn err_text(r: result[bool, str]) -> str {
    guard let _ok = r else let e = err_of(r) { return e; }
    return "";
}

fn test_age() {
    let at = timestamp_unix("2026-11-19T12:00:00.000Z") ?? 0;
    assert(check_age("2026-11-19T12:00:00.000Z", at + 3600, 3600) ?? false);
    assert(strings.contains(err_text(check_age("2026-11-19T12:00:00.000Z", at + 3601, 3600)), "3601 s old"));
    assert(check_age("garbage", at, 0) ?? false);
    assert(!(check_age("garbage", at, 60) ?? false));
}

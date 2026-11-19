# sns

An Amazon SNS client for slang. It publishes to topics (one message or a
batch), manages topics and subscriptions, and verifies the notifications
SNS posts to your HTTP(S) endpoint. It signs requests with the stdlib's
`sigv4` and works against AWS and LocalStack.

Needs slang 0.2.8 or later (the `sigv4` package).

```
pkg sns git https://github.com/dolphlabs/sns.git tag v0.1.0 dir src/sns
```

```slang
import "proc";
import "sns";

let r = sns.from_env(proc.getenv);   // AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
                                     // AWS_SESSION_TOKEN, SNS_ENDPOINT
guard let c = r else let e = err_of(r) { panic(e); }
sns.publish(c, topic_arn, "{\"order\":42}", deadline);     // ok(Published): id, sequence (FIFO)

let m = sns.outgoing("{\"order\":43}");
m.subject = "Order 43";
m.attributes["kind"] = "refund";                            // for subscription filter policies
sns.publish_message(c, topic_arn, m, deadline);
sns.publish_batch(c, topic_arn, [sns.outgoing("a"), sns.outgoing("b")], deadline);
```

## Receiving notifications

SNS signs every message it posts to an HTTP(S) subscriber. Check the
signature before you trust the message:

```slang
let v = sns.new_verifier();          // make it once; it caches certificates
// in the handler, with the request body:
let nr = sns.verify(v, to_str(body), deadline);
guard let n = nr else let e = err_of(nr) { return bad_request(e); }
if n.kind == "SubscriptionConfirmation" {
    sns.confirm(v, n, deadline);     // fetches the verified SubscribeURL
} else {
    // n.message, n.subject, n.topic_arn, n.id
}
```

`verify` checks:
- The signing certificate URL is `https://sns.<region>.amazonaws.com/...pem`
  (or `.com.cn`). Any other URL is refused, because a certificate there
  would be one an attacker chose.
- The certificate is fetched over verified TLS, is valid now, and is cached.
- The signature is SignatureVersion 2 (SHA-256). Version 1 (SHA-1) is refused:
  set the topic's `SignatureVersion` attribute to `2`, for example with
  `sns.set_topic_attribute(c, arn, "SignatureVersion", "2", dl)`.
- The message is at most `v.max_age` seconds old (an hour by default), so an
  old, validly signed message cannot be replayed.
- A confirmation's `SubscribeURL` is also an SNS URL, so confirming it cannot
  send a request anywhere else.

Topics: `create_topic` (attributes by SNS's names), `delete_topic`,
`set_topic_attribute`, `subscribe`, `unsubscribe`. Errors carry SNS's code:
`sns: NotFound: Topic does not exist`.

Not yet: SMS and mobile push (`PhoneNumber` and `TargetArn`), binary message
attributes, and automatic retries on throttling.

`make test` runs the unit tests. The client has not yet been run against
AWS or LocalStack. MIT licence.

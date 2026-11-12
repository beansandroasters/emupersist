# emupersist

English | [日本語](README.ja.md)

[AWS Emulator](https://github.com/aws/aws-emulator) keeps its state in memory only, so everything is lost when it stops.
emupersist is an HTTP proxy that sits in front of the emulator. **It records every request that changed state, and replays them in the same order the next time it starts.**
The journal can be stored in a local file, SQLite, DynamoDB, or S3.

```
SDK / CLI ──HTTP──▶ emupersist :4566 ──HTTPS──▶ aws-emulator (-a off, child process)
                       │  appends write requests that returned 2xx
                       ▼
                 journal (file / sqlite / dynamodb / s3)
```

- A single binary (4.5 MB release build on x86_64 Linux)
- Minimal dependencies: no async runtime, no HTTP framework, no AWS SDK ([Dependencies](#dependencies))
- Random IDs that change on every replay look unchanged to clients ([ID mapping](#ids-that-change-across-restarts))

> AWS Emulator is a product of Amazon Web Services. This is an independent tool and is not affiliated with AWS.
> Like AWS Emulator itself, it is meant for development and testing, not for production.

## Why record requests instead of snapshotting state?

emupersist does not save the emulator's state as a whole (a snapshot).
The state lives in memory as one Rust struct per service, and most of it is not in a serializable form.
Making it serializable would mean maintaining a fork of the emulator, which could not keep up with its frequent releases.

The HTTP interface, on the other hand, is the same for every service, and the emulator has an `-a off` option that turns off signature verification.
So emupersist leaves the emulator's internals alone and rebuilds state from outside, over HTTP (event sourcing).
This keeps working as the emulator adds services.

## Build

```bash
cargo build --release                         # with SQLite (needs a C compiler)
cargo build --release --no-default-features   # without SQLite (pure-Rust dependencies only)
```

Requires Rust 1.89 or later (the highest minimum among the dependencies).
Install aws-emulator by following the [official guide](https://docs.aws.amazon.com/emulator/latest/userguide/getting-started-linux.html).

## Usage

```bash
# put aws-emulator on PATH, or pass its location with --emulator
./target/release/emupersist run --store file:.emupersist/journal.jsonl -- -t off

# in another shell
export AWS_ENDPOINT_URL=http://127.0.0.1:4566 AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=AKIATEST AWS_SECRET_ACCESS_KEY=dummy
aws dynamodb list-tables
```

Arguments after `--` are passed to aws-emulator as is (the example turns telemetry off).
Stop with Ctrl-C and `run` again: emupersist replays the journal before it starts listening.

| Command | What it does |
|---|---|
| `emupersist run` | Starts aws-emulator as a child process (`-b 127.0.0.1 -p 0 -a off`), replays, then listens |
| `emupersist proxy --upstream URL --ca FILE` | Sits in front of an emulator you started yourself. It must run with `-a off` and start empty |
| `emupersist inspect` | Lists the recorded requests |
| `emupersist reset` | Deletes the whole journal |
| `emupersist init-store` | Creates the DynamoDB table for the journal |

Main options (see `emupersist --help` for all of them):

- `--store URL` (env `EMUPERSIST_STORE`)
- `--namespace NAME`
- `--port` (default 4566; 0 picks a free port)
- `--bind` (default 127.0.0.1)
- `--allow-origin ORIGIN` (accept requests from browsers on this origin; see [Security](#security))
- `--max-body-bytes N` (largest request body accepted; default 512 MiB)
- `--write-op OP` / `--read-op OP` (override whether an operation counts as a write)
- `--replay-retry-seconds` (total time spent retrying during replay; default 30)
- `--strict` (refuse to start if any request fails to replay)

While running, emupersist serves admin routes:

- `GET /__persist/status` returns the record count, the store, the number of ID mappings, and whether recording has failed
- `GET /__persist/journal` returns the list of records (without bodies)
- `POST /__persist/reset` deletes the journal and restarts the emulator (`run` only)

## Stores

There is no configuration file. You pass the store as a URL.

```bash
emupersist run --store file:.emupersist/journal.jsonl
emupersist run --store sqlite:./state.db --namespace feature-x
emupersist init-store --store "dynamodb://my-journal?region=ap-northeast-1"   # create the table
emupersist run        --store "dynamodb://my-journal?region=ap-northeast-1"
emupersist run        --store "s3://my-bucket/emupersist?region=ap-northeast-1&profile=dev"
```

| Store | Good for | Concurrent writers | Notes |
|---|---|---|---|
| `file:` | Local development; human-readable | Not detected | fsync per record. A half-written last line is truncated on load. Created with mode 0600 |
| `sqlite:` | Switching between several local states (`--namespace`) | Detected by primary key | Opened in WAL mode. Created with mode 0600. Feature `sqlite` (on by default) |
| `dynamodb://` | Sharing state across a team or CI | Detected by conditional writes | Records over 400 KB are split. About 5 ms per append |
| `s3://` | Caching state between CI runs; states with large S3 objects | Detected by `If-None-Match: *` | Startup issues one GET per record. About 26 ms per append |

Append times are the average of 10 writes from an EC2 instance in ap-northeast-1 to the same region.

Namespaces may contain only letters, digits, `.`, `_` and `-`.
Writes to DynamoDB and S3 are retried with backoff on network errors, 5xx responses and throttling.
If a conditional write collides with an item or object whose content is exactly what was being written, it is treated as success, because it is this process's own earlier attempt whose response was lost.

DynamoDB and S3 URLs accept `region=`, `profile=`, `endpoint=` and `ca=`.
Credentials are looked up in this order: environment variables, static keys in `~/.aws/credentials`, then `credential_process`.
SSO and `role_arn` chains are not supported. For those, put the output of `aws configure export-credentials --profile NAME --format env` into the environment.

Stores that were considered and left out:

- **Redis / ElastiCache**: good at appends, but adds one more server to run locally
- **PostgreSQL / Aurora**: shareable, but the driver adds dependencies
- **SQLite on a shared file system**: file locks over the network cannot be trusted; use DynamoDB to share
- **A Git repository**: a commit per request is too heavy; commit a `file:` journal yourself to get the same effect

## IDs that change across restarts

Some emulator IDs are sequential, and some are random.
For example, EC2 VPC IDs are sequential (`vpc-00000000000000080`).
Secrets Manager ARN suffixes, KMS key IDs, and IAM access keys are random.
Random IDs change on every replay, so an ARN a client saved before a restart no longer works after it.

So emupersist also records responses. During replay, it lines up each recorded response with the new one by structure,
and learns every string that sits at the same position with a different value as a mapping from the recorded ID to the current ID.
From then on, it rewrites requests to the current IDs before sending them to the emulator, and rewrites responses back to the recorded IDs before returning them.
To clients, IDs stay the same as when they first saw them.
Requests signed with an access key created through IAM are rewritten to the current key too, so `GetCallerIdentity` returns the right user.

Only paths, headers and text bodies (JSON / XML / form) are rewritten.
S3 object bodies are never touched, even when their content type is JSON: they are user data, protected by checksums.
Bucket configuration bodies (`?encryption`, `?policy`, `?notification` and so on) can carry IDs, so they are rewritten.
When a body is rewritten, the integrity headers tied to it are recomputed: `x-amz-crc32` (DynamoDB), `Content-MD5`, `x-amz-checksum-*` and `x-amz-content-sha256`.

Learning a value that is supposed to change, such as a status (`PENDING` to `RUNNING`), would make emupersist rewrite unrelated requests.
So the following are never learned:

- timestamps, numbers, booleans, HTTP dates, and values shorter than 6 characters
- values that contain no digit, `:` or `/`, have no mixed case inside the word, and are not a run of 16 or more letters and digits (English words and enum values such as `available` or `CREATE_IN_PROGRESS`)
- fields whose names end in RequestId, Token, Status, State, Message, and similar

## Known limitations

- **Time-dependent state is rebuilt at replay time.** SQS retention, DynamoDB TTL, credential expiry and so on count from startup, not from when the request was recorded.
- **Asynchronous state transitions are handled by retrying.** A table is `CREATING` right after CreateTable, so the next PutItem fails once during replay.
  A request that succeeded when recorded but fails now is retried with growing intervals.
  The total time spent retrying across the whole replay is capped by `--replay-retry-seconds`, so that a version change causing many mismatches does not stall startup for long.
  A failed request did not change state, so retrying cannot apply it twice.
- **Concurrent writes are recorded in the order their responses returned.** Two requests that ran in parallel can be recorded in a different order from the one the emulator applied.
- **The journal only grows.** The internal state cannot be serialized, so the journal cannot be compacted. Run `reset` to start over when needed.
- **Whether a request is a write is a guess.** RPC operations are judged by name prefix (`Describe*` / `List*` / `Get*` ...), and REST operations by HTTP method.
  When unsure, the request is recorded as a write. Use `--write-op` / `--read-op` when the guess is wrong.
  SQS ReceiveMessage is not recorded only when it returned no messages, so that polling does not grow the journal.
- **ID mapping is a guess too.** Values that do not look like IDs are excluded (see [above](#ids-that-change-across-restarts)), but a string that happens to match a learned ID could still be rewritten.
- **A different emulator version can replay differently.** Each record carries the emulator version, and emupersist warns at startup if it differs.
- **Side effects the emulator keeps as state are reproduced by replaying the original request.** For example, Lambda Invoke runs the function again.
- **The front end speaks plain HTTP only.** SDKs accept `http://` endpoints, but clients that require HTTPS cannot use emupersist.
- **Request bodies are held in memory.** Bodies over `--max-body-bytes` (default 512 MiB) are rejected with 413.
- **Child cleanup on abnormal exit is Linux-only.** On Linux, the emulator gets SIGTERM even if emupersist is killed with SIGKILL (`PR_SET_PDEATHSIG`). On macOS, the emulator is stopped only when emupersist exits through SIGTERM or Ctrl-C.

## Security

- The emulator behind emupersist does not verify signatures (`-a off`). The emulator's credentials change on every start, so recorded signatures would not verify after a restart.
  emupersist listens on 127.0.0.1 only by default. If you open it with `--bind`, anyone who can reach it can change or reset the state (the admin routes have no authentication either).
- Listening on 127.0.0.1 is not enough on its own: a malicious web page opened in your browser can still send requests to it. emupersist blocks two such attacks.
  - **CSRF**: requests carrying an `Origin` header are rejected with 403, since browsers attach it to cross-origin POSTs and fetches. To use a browser SDK, allow its origin with `--allow-origin http://localhost:3000` (repeatable; `*` allows any).
  - **DNS rebinding**: requests whose `Host` is not a loopback name (127.0.0.1, localhost, ::1) or the bind address are rejected. This check is skipped when binding to an unspecified address such as 0.0.0.0.
- Malformed input is rejected rather than trusted: oversized bodies (413), oversized headers (431), truncated chunked bodies, and requests carrying both `Transfer-Encoding` and `Content-Length`. Up to 512 connections are served at once, and idle connections are closed after 300 seconds.
- Records have the signature in Authorization and in presigned URLs redacted, and `X-Amz-Security-Token` dropped.
- **The journal contains request bodies verbatim** (secret values, access key IDs, and so on). Put only test values in it.
  `.gitignore` excludes the default location `.emupersist/` as well as `*.jsonl` and `*.db`.

## Dependencies

TLS is unavoidable for talking to the emulator, so it is left to rustls. Everything else is written on the standard library.

| Direct dependency | Used for | Not used instead |
|---|---|---|
| `rustls` (ring, std, tls12 only) | HTTPS to the emulator and to AWS | OpenSSL (depends on the system) |
| `webpki-roots` | Root certificates for AWS (data only) | `rustls-native-certs` (per-OS dependencies) |
| `ring` | SHA-256 / HMAC for SigV4; already pulled in by rustls | `sha2` + `hmac` |
| `serde_json` | JSON; only `Value` is used, no derive macros | `serde_derive` (proc-macro stack) |
| `miniz_oxide` | zlib for records stored in DynamoDB / S3 | `flate2` |
| `libc` | Sending and receiving SIGTERM; already pulled in by ring | `signal-hook`, `nix` |
| `rusqlite` (bundled, feature `sqlite`) | The SQLite store | — |

Written on std alone:

- HTTP/1.1 server and client (keep-alive, chunked, `Expect: 100-continue`)
- Argument parsing
- base64, URI encoding, dates, CRC32
- Reading the ListObjectsV2 XML

The dependency tree (`cargo tree -e normal`, excluding the crate itself) has 28 crates by default and 19 with `--no-default-features`.

## Measurements

Measured on 2026-11-12 with aws-emulator 1.0.322 on an EC2 r6a.2xlarge, using one keep-alive connection from a single client.

| Item | Value |
|---|---|
| PutItem through emupersist (including recording and fsync) | 0.56 ms per request |
| GetItem through emupersist (not recorded) | 0.50 ms per request |
| Reference: PutItem / GetItem sent directly to the emulator | 0.40 / 0.41 ms per request |
| Replaying 2,001 requests (including about 3 s waiting for CreateTable to become ACTIVE) | 3.8 s |
| Journal for 2,000 requests (200-byte items) | 2.3 MB |

## Tests

```bash
cargo test                                                  # unit tests
EMUPERSIST_TEST_EMULATOR=/path/to/aws-emulator cargo test   # also round-trip tests against a real emulator
```

The round-trip tests check that:

- DynamoDB items, KMS key IDs and aliases, and S3 binaries (byte for byte) survive a restart
- an S3 object whose JSON content contains a mapped ID comes back unchanged
- HEAD returns the right Content-Length, and empty receives are not recorded
- reset works, and the new emulator stays alive after the connection that asked for it closes
- a journal in format v1 (`tests/fixtures/journal-v1.jsonl`) replays as is
- hostile input (a huge Content-Length, CSRF, DNS rebinding, a truncated chunked body) is rejected without crashing or recording anything
- on Linux, the emulator does not outlive an emupersist killed with SIGKILL

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

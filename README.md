# siem

[![CI](https://github.com/openasy/siem/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/siem/actions/workflows/ci.yml)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) SIEM product: security events come in, [Sigma](https://sigmahq.io/) rules
look at every one of them, and what they find is kept as **signals** to investigate and close (ADR 0040).

```
shippers, agents, scripts ──POST /api/v1/events──▶  siem  ──every event through every rule that is on──▶  signals
                                                    └── events kept for 30 days, searchable
```

One rule on one host within a window (60 minutes by default) is one signal, with a count and the first events, so a
thousand failed logins are one thing to look at. A signal you close or mark as a false positive stops collecting
matches: the next match is a new signal.

## Events

Events are flat JSON objects: text, numbers, true/false or null. `time` (ISO 8601 or milliseconds since 1970) defaults
to now; `host`, `source` and `message` are what search and signals use; everything else is kept as sent and can be
matched by rules. Send one event or an array of up to 1000, optionally gzipped, up to 16 MiB. If one event in a request
is not valid, none is kept and the message names it.

```bash
curl -sf -X POST -H "Authorization: Bearer $SIEM_INGEST_TOKEN" -H 'content-type: application/json' \
  -d '{"host":"web-1","source":"sshd","message":"Failed password for root from 10.0.0.9"}' \
  http://localhost:8080/api/v1/events
```

## Rules

Rules are Sigma, written as YAML or as JSON. A rule that cannot be read is refused with the line or the name that is
wrong, and **Test against recent events** (or `POST /api/v1/rules/test`) shows what a rule would have matched before it
goes live.

```yaml
title: Failed SSH login
level: medium
detection:
  selection:
    source: sshd
    message|contains: 'Failed password'
  condition: selection
```

Supported: selections as maps of fields (a list of values means any), lists of maps (any), and keyword lists;
the modifiers `contains`, `startswith`, `endswith`, `re` and `all`; wildcards `*` and `?` in values (`\*` and `\\` for
the characters themselves); conditions with `and`, `or`, `not`, parentheses, and `1 of`, `any of` and `all of` over
names, patterns (`filter_*`) and `them`. Text is compared without regard to case; `re` is case-sensitive.
`level` is critical, high, medium, low or informational (shown as low). Not supported yet, and said so when you try:
aggregations (`| count()`), `timeframe`, and other modifiers such as `base64` or `cidr`.

The YAML reader is built in and covers what Sigma rules use: maps, lists, quoted and block scalars, inline lists and
comments. Anchors, tags and flow maps are refused; write the rule as JSON instead if you need something else. Regular
expressions that can backtrack without end, such as `(a+)+`, are refused.

A rule that fails on an event is noted on the rule (`lastError`) and skipped; events are always kept.

## Run

```bash
openssl rand -hex 32 > openasy-kek
export SIEM_INGEST_TOKEN=$(openssl rand -hex 32)
docker compose up -d
docker compose logs siem | grep 'no owner yet'
```

Open the link from the log once to create the owner account; there is no default password (ADR 0013). The UI and API
are on http://localhost:8080, the API reference at http://localhost:8080/api/docs/.

`openasy-kek` encrypts sign-in secrets in siem's database (ADR 0021). Keep it apart from the volume and with your
backups.

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `SIEM_PUBLIC_URL` | `http://localhost:8080` | The address people open, with `https://` behind your TLS proxy |
| `OPENASY_PRODUCTS` | | The install's other OpenAsy products, for the product switcher. Give every product the same value |
| `SIEM_INGEST_TOKEN` | | Lets shippers send events and nothing else. An API token with the editor role works too |
| `SIEM_SECRETS_KEY_FILE` | `/run/secrets/openasy-kek` | 32-byte key-encryption key |
| `SIEM_DB` | `/data/siem.db` | SQLite file (WAL), on the `/data` volume |
| `SIEM_RETENTION_DAYS` | `30` | Events, and closed signals, older than this are deleted |
| `SIEM_SIGNAL_WINDOW_MINUTES` | `60` | Matches of one rule on one host closer together than this are one signal |
| `SIEM_METRICS_PORT` | | Serve `/metrics` on this port only (ADR 0026) |
| `SIEM_HEADLESS` | `false` | `true` serves only the API |
| `SIEM_PASSWORD_SIGN_IN`, `SIEM_OIDC_*` | | Sign-in, as in every OpenAsy product ([@openasy/auth](https://github.com/openasy/auth)). Owners can also add identity providers under Settings, Sign-in |

The container runs as non-root with a read-only root filesystem, no capabilities and `no-new-privileges`.

Events hold whatever the shippers send, which can include personal data and secrets. Anyone with the viewer role reads
them, and they are deleted after the retention period.

## Roles

Viewers see everything; editors also work signals (investigate, close) and test rules; admins also add, change and
delete rules, and manage members and API tokens (ADR 0003).

## Develop

```bash
npm install
npm test        # the Sigma reader and evaluator, events, signals, and every API response against openapi.json
npm run dev     # the UI, with the API on :8080
```

## Licence

AGPL-3.0 (ADR 0008).

# Planetary Probe

**Category:** Web &nbsp;|&nbsp; **Points:** 474 &nbsp;|&nbsp; **Solves:** 147 &nbsp;|&nbsp; **Flag:** `sun{bl1nd_psqli_2_rc3_p4Nd0FyZt8k2}`

## Challenge description

> The Galactic Federation has opened public access to its Planetary Probe Directory, a
> database of known planets and their telemetry signatures. Your mission is to interface
> with the probe console and uncover hidden data the Federation would rather keep secret.
>
> The console seems… minimal. No verbose errors, no detailed output — just "signal
> detected" or "no signal". Can you find a way to communicate with the system, bypass its
> limited responses, and recover the hidden flag?
>
> `https://planetary.web.2026.sunshinectf.games/`

## Initial analysis

The index page has one form: `GET /probe?planet=MARS`. The response never shows data —
it only encodes a single bit in the `<body>` class:

| Body class | Meaning |
| --- | --- |
| `is-carrier` | signal detected → condition **true** |
| `is-null` | no signal → condition **false** |
| `is-standby` | initial page (no query) |

That is the textbook shape of a **boolean-based blind injection oracle**: one bit per request.

Probing the `planet` parameter confirms SQL injection in a single-quoted string context:

```
MARS' AND '1'='1   → is-carrier (true)
MARS' AND '1'='2   → is-null    (false)
```

Fingerprinting the DBMS: `current_database()`, `pg_database`, and `pg_class` all work
while `sqlite_version()` fails → **PostgreSQL** (or a Postgres-compatible engine).

## Core concept

Two things combine here, which is exactly what the flag spells out — **blind PostgreSQL
injection escalated to RCE** (`bl1nd_psqli_2_rc3`):

1. **Boolean-blind SQLi** gives a one-bit oracle: `true`/`false` per request.
2. The injection point allows **stacked queries**, so we can run PostgreSQL's
   `COPY ... TO PROGRAM`, which executes a shell command on the database server. The flag
   isn't in the database at all — it's a file on disk (`/flag.txt`), readable only via
   command execution.

So we bootstrap a bit-oracle out of the command's *success/failure*, then binary-search
the flag one character at a time by asking shell predicates about `/flag.txt`.

## Solving process

### The oracle

Everything is driven through `oracle.py` / [`solve.py`](./solve.py), which wrap the
`is-carrier` / `is-null` response into a `truth(condition)` predicate. A gotcha from
`analysis.md`: the server is **slow (~2–5 s/request) and flaky under concurrency**, so
the oracle re-confirms each bit and retries, treating only consistent results as real.

### From blind SQLi to a command oracle

`COPY (SELECT 1) TO PROGRAM '<cmd>'` runs `<cmd>` on the server. If the command exits
non-zero, the `COPY` aborts and the trailing `SELECT 1` never fires → `is-null`. If the
command succeeds, we get `SELECT 1` → `is-carrier`. That turns any shell predicate into
one oracle bit. From [`extract_flag.py`](./extract_flag.py):

```python
shell = "cat >/dev/null; " + predicate      # drain COPY stdin, then test
sql = "'; COPY (SELECT 1) TO PROGRAM '" + shell + "'; SELECT 1; -- -"
# is-carrier  => predicate exited 0 (true bit)
# is-null     => predicate exited non-zero (false bit)
```

### Extracting `/flag.txt` byte by byte

First the length, by doubling then binary-searching:

```python
"f=$(cat /flag.txt); test ${#f} -gt {n}"
```

Then each character, binary-searched over its byte value and then confirmed with an
equality test (to defeat the flaky bits):

```python
prefix = f"set -- $(head -c {position} /flag.txt | tail -c 1 | od -t u1); test \"$2\" "
#   ... -gt {mid}   (binary search)
#   ... -eq {lo}    (confirm)
```

A `ThreadPoolExecutor` runs a few positions in parallel and checkpoints every recovered
character to `.flag-progress.json`, so an interrupted run resumes instead of re-querying.

## Flag retrieval

Running `extract_flag.py` walks all 35 positions and assembles:

```
sun{bl1nd_psqli_2_rc3_p4Nd0FyZt8k2}
```

(Notably the flag was **never in the database** — the planets table held only vanilla
planet facts. It had to be read off the filesystem via `COPY TO PROGRAM`.)

## Key takeaways

- A single true/false tell (here, a CSS class) is enough to build a full blind-SQLi
  oracle — no error messages or echoed data required.
- On PostgreSQL, **stacked queries + `COPY ... TO PROGRAM` = RCE.** When blind SQLi won't
  reach the secret, pivot to command execution and read the filesystem.
- Encode the command's exit status into your oracle (`cmd && SELECT 1`) to extract
  arbitrary file contents one bit at a time.
- Design for a slow, flaky target: re-confirm bits, retry, and checkpoint progress.

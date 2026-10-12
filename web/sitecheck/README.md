# SiteCheck

**Category:** Web &nbsp;|&nbsp; **Points:** 474 &nbsp;|&nbsp; **Solves:** 147 &nbsp;|&nbsp; **Flag:** `sun{fr4gm3nt3d_r3fl3ct10ns_1n_th3_futur3}`

## Challenge description

> Welcome to **SiteCheck**, the SkyCity fleet's favorite web-diagnostics service since 2062!
> Enlist for a free inspector account and put any website through its paces: our autonomous
> inspection drone flies out to the address you provide, clocks how long the page takes to
> load, tallies how many files it pulls down, and beams back a crisp viewport snapshot.
>
> *The drone politely refuses to inspect internal or local addresses. Safety first!*
>
> `https://spaceship.web.2026.sunshinectf.games`

## Initial analysis

SiteCheck lets a registered user ask an "inspection drone" to visit a URL. The drone is
really a **headless browser**: it loads the page, counts the requests, and returns a
**1280 × 800 screenshot** that we can view afterward.

After registering, `/profile` shows my account at **BRONZE** clearance. Near the bottom
is a "Clearance Data" section whose token is replaced with:

> `REDACTED · insufficient clearance`

The page also has a `#clearance` anchor, and its CSS deliberately pushes that section
*below* the first screenshot-sized viewport.

Two clues stand out: the explicit "no internal/local addresses" warning (a dare), and the
fact that the only thing the drone gives back is a **screenshot** of a viewport.

## Core concept

**Server-Side Request Forgery (SSRF)** through the drone browser, with two twists:

1. The loopback blocklist is incomplete — it blocks a few spellings of localhost but not
   the whole `127.0.0.0/8` range.
2. The drone's browser is **logged in as `admin`** when it visits the app on a loopback
   host, so pointing it at the app's own `/profile` renders the privileged page.
3. We only get a screenshot, so we use a **URL fragment (`#clearance`)** to scroll the
   browser straight to the classified section before the snapshot is taken.

## Solving process

### Bypass the local-address filter

The form rejects `http://127.0.0.1:3000/` and `http://localhost:3000/`. But `127.0.0.1`
is only one of 16 million loopback addresses — the entire `127.0.0.0/8` block routes back
to the same machine. The filter missed `127.0.0.2`:

```
http://127.0.0.2:3000/profile#clearance
```

When the drone fetched the app via `127.0.0.2`, its browser session was **admin**
(cookies are host-scoped, so only certain loopback names carried the privileged session —
others landed on the sign-in page). A fragment-less scan of `/profile` confirmed
"Inspector: admin" with **OMEGA** clearance.

### Frame the secret into the screenshot

Because we only receive a viewport snapshot, the `#clearance` fragment makes the headless
browser jump directly to the classified "Clearance Data" section, so the token lands
inside the 1280 × 800 image instead of off-screen.

### Reproduce with a logged-in cookie jar

```bash
SITE='https://spaceship.web.2026.sunshinectf.games'
curl -i -b cookies.txt -X POST "$SITE/scan" \
  --data-urlencode 'url=http://127.0.0.2:3000/profile#clearance'
```

Follow the `Location: /result/<id>` header, then open the `/screenshots/<id>.png` image
linked in the report. ([`probe.sh`](./probe.sh) is the account/scan helper and
[`words.txt`](./words.txt) the small route list used while mapping the app.)

## Flag retrieval

The screenshot opens right at the classified section, where the token reads:

```
sun{fr4gm3nt3d_r3fl3ct10ns_1n_th3_futur3}
```

## Key takeaways

- Loopback blocklists that only match `127.0.0.1`/`localhost` are trivially bypassed —
  the whole `127.0.0.0/8` range (and `0.0.0.0`, IPv6 `::1`, decimal/hex IP encodings) is
  loopback too.
- An SSRF primitive is far more dangerous when the fetcher is **authenticated** — here the
  drone browsed its own app as `admin`.
- Screenshot-only SSRF can still exfiltrate text: use a **URL fragment** to position the
  target content inside the captured viewport.

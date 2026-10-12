# VecNet

**Category:** Misc &nbsp;|&nbsp; **Points:** 482 &nbsp;|&nbsp; **Solves:** 124 &nbsp;|&nbsp; **Flag:** `sun{k33p_your_emb3ddings_secur3!}`

## Challenge description

> VecNet makes use of AI embedding technologies to speed up your database needs. Get started today!
>
> `https://vec.web.2026.sunshinectf.games/`

## Initial analysis

VecNet is a web front for a vector/embedding database. The landing page links to a
MailHog UI (`http://vec.web.2026.sunshinectf.games:8025/`) — note the `http` link on an
`https` site, a protocol mismatch worth remembering.

The first real foothold is a classic: **`/.git/HEAD` is publicly readable.** When the
`.git` directory ships to production, the whole source history is recoverable object by
object.

## Core concept

This challenge is a multi-stage chain that ends in an **AI-specific trick**: inverting a
text embedding back into (approximately) its original text to recover a password rule.
The stages are:

1. **Exposed `.git`** → recover source history, including a historical `config.php`.
2. **Leaked credentials + a whitelisted fetch proxy** → pull the encrypted archive.
3. **An embedding-only clue in the vector DB** → invert it with `vec2text`.
4. **Crack a short password from a known hash + the recovered rule** → decrypt the flag.

## Solving process

### 1. Dump the exposed Git history

[`dump_git.py`](./dump_git.py) reads `/.git/HEAD`, follows the ref to a commit, then
recursively walks every `commit → tree → blob` object, decompressing each with `zlib`:

```python
BASE = "https://vec.web.2026.sunshinectf.games/.git/"
head = get("HEAD")                      # ref: refs/heads/master
sha  = get(ref).decode().strip()        # tip commit
fetch(sha)                              # recurse tree/parent objects
```

This recovered five commits. A historical `config.php` (commit `c3cd120`) disclosed the
**MailHog basic-auth credentials**, and a historical `fetch.php` revealed a server-side
fetch route whitelisted to exactly one URL: `http://localhost/files/specs.7z`.

### 2. Retrieve the encrypted archive

Directly requesting `/files/specs.7z` returns `403`. But the recovered `fetch.php` route
happily serves that exact local URL back to us — a built-in SSRF/whitelist bypass. The
result is [`specs.7z`](./specs.7z), which contains an **encrypted** `flag.txt`. The
leaked MailHog password did *not* open it, so the password lives elsewhere.

### 3. Read the mail, find the vector store

Authenticating to the MailHog API (`/api/v2/messages`) returned three messages. Two were
load-bearing:

- One disclosed the `vec2text` parameters: **`num_steps=4`, `sequence_beam_width=5`**.
- One identified the vector store as **ChromaDB**.

The ChromaDB-compatible API (port 8000) exposed a collection `VecNetDB`. Its `/query`
route was blocked, but `/get` was not — and it returned an item called
`user_password_requirements` as a **768-dimension embedding only** (no plaintext),
along with a SHA-256 hash and a magic string `sunshinectf8_`. The metadata named the
embedding model: `jxm/gtr__nq__32` → GTR-base, the model `vec2text` ships a corrector for.
See [`collection.json`](./collection.json) for the raw response and
[`hash.txt`](./hash.txt) for the target hash.

### 4. Invert the embedding (the AI part)

`vec2text` can approximately reverse a sentence embedding back to text. [`invert.py`](./invert.py)
loads the GTR-base corrector and inverts the leaked vector with the exact parameters the
mail disclosed (this is GPU work — it was offloaded to a GPU host):

```python
corrector = vec2text.load_pretrained_corrector("gtr-base")
result = vec2text.invert_embeddings(
    embeddings=embedding,          # the 768-d vector from collection.json
    corrector=corrector,
    num_steps=4,
    sequence_beam_width=5,
)
```

Reconstructed text:

> *The user's first and last initials, three special characters followed by the magic string.*

### 5. Crack the archive password

The recovered rule + the known SHA-256 define a tiny search space:
`<initial><initial><special><special><special>sunshinectf8_`. GPU hashcat found the exact
preimage almost instantly:

```
GR$*#sunshinectf8_
```

That password decrypts `specs.7z`:

```bash
7z x specs.7z -p'GR$*#sunshinectf8_'
cat flag.txt
```

## Flag

```
sun{k33p_your_emb3ddings_secur3!}
```

## Key takeaways

- A leaked `.git` directory is a full-source disclosure; always try `/.git/HEAD`.
- Old secrets and whitelisted internal routes live in **git history**, not just `HEAD`.
- **Embeddings are not one-way.** `vec2text` can recover the text behind a sentence
  embedding closely enough to use. "Embedding-only" is not a safe way to store a secret —
  exactly what the flag says.
- Chain discipline: creds → proxy → vector store → embedding inversion → hash crack.
  Each link only makes sense once you have the previous one.

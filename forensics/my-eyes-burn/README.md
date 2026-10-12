# my eyes burn

**Category:** Forensics &nbsp;|&nbsp; **Points:** 312 &nbsp;|&nbsp; **Solves:** 389 &nbsp;|&nbsp; **Flag:** `sun{praisethesun}`

## Challenge description

> anon hasn't been outside in years, so he put the sun in his keyboard. find the flag he types to bring it out.

The only attachment is `boardwriter.klc`.

## Initial analysis

`file` isn't much help on a `.klc`, but the extension is the giveaway: it's a
**Microsoft Keyboard Layout Creator (MSKLC)** source file. These are UTF-16LE text,
so the first move is just to read it:

```bash
iconv -f utf-16 -t utf-8 boardwriter.klc | less
```

The `LAYOUT` section is an ordinary US keyboard with one odd entry:

```
29	OEM_3	0	0060@
```

That trailing `@` marks the backtick key (`` ` ``, `U+0060`) as a **dead key** — a key
that doesn't emit a character on its own but modifies the next key you press (think of
typing an accent before a vowel).

Below the layout are **17 `DEADKEY` tables**. Each one has exactly one mapping, and the
result of that mapping is *another* dead key (it also ends in `@`). In other words, the
keyboard is a hand-rolled state machine: press the backtick to arm the first dead key,
then each letter you type walks you to the next dead-key state.

## Core concept

This is a **dead-key chain**. The description is a literal instruction set:

- "he put the sun in his keyboard" → the chain terminates at `U+2600 ☀ BLACK SUN WITH RAYS`.
- "find the flag he types to bring it out" → the sequence of keystrokes that walks the
  chain from the backtick to the sun **is the flag**.

Each dead-key table maps one input character to the next state, so following the chain
end-to-end spells out exactly what `anon` types.

## Solving process

Rather than trace 17 tables by hand, [`solve.py`](./solve.py) parses every `DEADKEY`
block into a `state -> (input_char, next_state)` dictionary and walks it starting from
`0060` (the backtick), collecting each input character until a mapping produces a real
character instead of another dead key:

```python
import re
t = open('boardwriter.klc', 'rb').read().decode('utf-16')
dk = {}
for m in re.finditer(r'DEADKEY\t(\w+)\r?\n(\w+)\t(\w+@?)', t):
    dk[m.group(1)] = (m.group(2), m.group(3))

state, out = '0060', ''
while state in dk:
    k, r = dk[state]
    out += chr(int(k, 16))
    if not r.endswith('@'):          # reached a terminal character
        print('final char:', chr(int(r, 16)))
        break
    state = r[:-1]                   # strip the '@' to get the next state
print(out)
```

Running it walks the whole chain — all 17 tables are consumed, with no branches or
decoys:

```
dead 0060 + 's' -> 02d0@
dead 02d0 + 'u' -> 02ed@
...
dead 02e1 + 'n' -> 02b0@
dead 02b0 + '}' -> 2600
final char: ☀
sun{praisethesun}
```

## Flag

```
sun{praisethesun}
```

Typing `` ` `` and then `sun{praisethesun}` on this layout really does end by emitting
a `☀` — "bringing out the sun."

## Key takeaways

- **Know your file formats.** `.klc` → MSKLC keyboard layout, UTF-16LE text. Recognising
  the format is 80% of the challenge.
- Dead keys chain. A layout full of single-entry dead-key tables is a state machine, and
  the path through it is the intended "password".
- Read the flavour text literally — "put the sun in his keyboard" and "bring it out"
  both describe the terminal `☀` glyph.

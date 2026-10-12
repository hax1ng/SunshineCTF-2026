#!/usr/bin/env python3
"""Invert VecNetDB's embedding-only password clue with the advertised vec2text model."""
import json
import sys
import time

import torch
import vec2text

data = json.load(open("collection.json"))
idx = data["ids"].index("user_password_requirements")
embedding = torch.tensor([data["embeddings"][idx]], dtype=torch.float32).cuda()
print("embedding", data["ids"][idx], embedding.shape, flush=True)
t = time.monotonic()
corrector = vec2text.load_pretrained_corrector("gtr-base")
print("models loaded in", round(time.monotonic() - t, 1), "seconds", flush=True)

steps = int(sys.argv[1]) if len(sys.argv) > 1 else 4
beam = int(sys.argv[2]) if len(sys.argv) > 2 else 5
t = time.monotonic()
result = vec2text.invert_embeddings(
    embeddings=embedding,
    corrector=corrector,
    num_steps=steps,
    sequence_beam_width=beam,
)
print("inverted in", round(time.monotonic() - t, 1), "seconds", flush=True)
print(json.dumps(result, indent=2), flush=True)

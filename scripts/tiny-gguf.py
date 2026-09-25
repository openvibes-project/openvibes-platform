#!/usr/bin/env python3
"""Writes a tiny random-weight GGUF model (llama architecture, ASCII
SentencePiece vocabulary, under 1 MiB) for testing openvibes-llm under systemd.
Its answers are noise; it only proves the service loads a model and serves
the OpenAI-compatible API. Standard library only.

Usage: tiny-gguf.py OUTPUT.gguf
"""
import random
import struct
import sys

ALIGN = 32
N_EMBD, N_HEAD, N_LAYER, N_FF, N_CTX = 64, 4, 2, 128, 2048

U32, I32, F32, BOOL, STRING, ARRAY = 4, 5, 6, 7, 8, 9


def s(text):
    data = text.encode()
    return struct.pack("<Q", len(data)) + data


def kv(key, kind, value):
    out = s(key) + struct.pack("<I", kind)
    if kind == U32:
        return out + struct.pack("<I", value)
    if kind == I32:
        return out + struct.pack("<i", value)
    if kind == F32:
        return out + struct.pack("<f", value)
    if kind == STRING:
        return out + s(value)
    raise ValueError(kind)


def array(key, kind, values):
    out = s(key) + struct.pack("<IIQ", ARRAY, kind, len(values))
    for value in values:
        out += s(value) if kind == STRING else struct.pack({F32: "<f", I32: "<i"}[kind], value)
    return out


# SentencePiece needs a byte token for every byte it may meet, but a
# sampled byte >= 0x80 would be invalid UTF-8 on its own. The weights below
# keep those (and <s>, </s>) from ever being sampled: hidden dimension 0 is a
# constant the layers never write to, and the output layer scores it
# strongly negative for them.
tokens = ["<unk>", "<s>", "</s>", "\u2581"] + [chr(c) for c in range(33, 127)]
tokens += [f"<0x{b:02X}>" for b in range(256)]
types = [2, 3, 3] + [1] * 95 + [6] * 256
banned = {1, 2} | {98 + b for b in range(0x80, 0x100)}
TEMPLATE = (
    "{% for m in messages %}<|{{ m['role'] }}|>{{ m['content'] }}\n{% endfor %}"
    "{% if add_generation_prompt %}<|assistant|>{% endif %}"
)
meta = [
    kv("general.architecture", STRING, "llama"),
    kv("general.name", STRING, "openvibes-tiny-test"),
    kv("general.alignment", U32, ALIGN),
    kv("llama.context_length", U32, N_CTX),
    kv("llama.embedding_length", U32, N_EMBD),
    kv("llama.block_count", U32, N_LAYER),
    kv("llama.feed_forward_length", U32, N_FF),
    kv("llama.attention.head_count", U32, N_HEAD),
    kv("llama.attention.head_count_kv", U32, N_HEAD),
    kv("llama.rope.dimension_count", U32, N_EMBD // N_HEAD),
    kv("llama.attention.layer_norm_rms_epsilon", F32, 1e-5),
    kv("tokenizer.ggml.model", STRING, "llama"),
    array("tokenizer.ggml.tokens", STRING, tokens),
    array("tokenizer.ggml.scores", F32, [0.0] * 3 + [-1.0] * 95 + [-1000.0] * 256),
    array("tokenizer.ggml.token_type", I32, types),
    kv("tokenizer.ggml.unknown_token_id", U32, 0),
    kv("tokenizer.ggml.bos_token_id", U32, 1),
    kv("tokenizer.ggml.eos_token_id", U32, 2),
    kv("tokenizer.chat_template", STRING, TEMPLATE),
]

N_VOCAB = len(tokens)
shapes = [
    ("token_embd.weight", (N_EMBD, N_VOCAB)),
    ("output_norm.weight", (N_EMBD,)),
    ("output.weight", (N_EMBD, N_VOCAB)),
]
for i in range(N_LAYER):
    p = f"blk.{i}."
    shapes += [
        (p + "attn_norm.weight", (N_EMBD,)),
        (p + "attn_q.weight", (N_EMBD, N_EMBD)),
        (p + "attn_k.weight", (N_EMBD, N_EMBD)),
        (p + "attn_v.weight", (N_EMBD, N_EMBD)),
        (p + "attn_output.weight", (N_EMBD, N_EMBD)),
        (p + "ffn_norm.weight", (N_EMBD,)),
        (p + "ffn_gate.weight", (N_EMBD, N_FF)),
        (p + "ffn_up.weight", (N_EMBD, N_FF)),
        (p + "ffn_down.weight", (N_FF, N_EMBD)),
    ]

rng = random.Random(8484)


def values(name, dims):
    """Row-major data: dims[0] values per row, dims[1] rows."""
    cols, rows = dims[0], (dims[1] if len(dims) > 1 else 1)
    if name.endswith("norm.weight"):
        return [1.0] * cols
    out = []
    for row in range(rows):
        line = [rng.uniform(-0.1, 0.1) for _ in range(cols)]
        if name == "token_embd.weight":
            line[0] = 10.0  # the constant dimension
        elif name == "output.weight":
            line[0] = -1.0 if row in banned else 1.0
        elif row == 0 and name.endswith(("attn_output.weight", "ffn_down.weight")):
            line = [0.0] * cols  # layers never write the constant dimension
        out += line
    return out


infos, blobs, offset = b"", [], 0
for name, dims in shapes:
    data = values(name, dims)
    data = struct.pack(f"<{len(data)}f", *data)
    infos += s(name) + struct.pack("<I", len(dims)) + b"".join(struct.pack("<Q", d) for d in dims)
    infos += struct.pack("<IQ", 0, offset)  # type F32, offset in the data section
    padded = data + b"\0" * (-len(data) % ALIGN)
    blobs.append(padded)
    offset += len(padded)

header = b"GGUF" + struct.pack("<IQQ", 3, len(shapes), len(meta)) + b"".join(meta) + infos
header += b"\0" * (-len(header) % ALIGN)
with open(sys.argv[1], "wb") as out:
    out.write(header)
    for blob in blobs:
        out.write(blob)

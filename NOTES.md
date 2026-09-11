# NOTES: -fbounds-safety adoption (libxml2)

Google Patch Rewards — Tier-1 core infrastructure data parser (3× secure-by-design
memory-safety multiplier through end of 2026).

## Goal

Incremental, ABI-preserving adoption of Clang `-fbounds-safety` annotations so
pointer/buffer relationships become compiler-checked when the experimental option
is enabled. Default builds are unchanged (option **OFF**, macros **inert**).

## First CL (this draft) — scope limits

**One clear capacity-first pair only** — not a whole-library sweep:

| Site | Annotation | Bound |
|------|------------|-------|
| `struct _xmlBuf` (`buf.c`) | `content` ← `XML_SIZED_BY_OR_NULL(size)` | capacity (`size`), not `use` |

Rationale:

- `xmlBuf` is the internal growable buffer behind parser I/O and many writers.
- **Capacity-first**: bind the pointer to allocation capacity (`size`), not the
  logical length (`use`), so the compiler sees the full writable extent.
- `_or_null` matches existing NULL-tolerant buffer lifetimes.
- Macros in `include/libxml/boundsafety.h` expand to empty unless
  `LIBXML_BOUNDS_SAFETY` is defined **and** `__has_feature(bounds_safety)`.

Explicitly **out of scope** for this CL:

- Whole-library annotation sweep
- Enabling `-fbounds-safety` in default CI
- Parser-input `cur`/`end` (`__ended_by`) — natural follow-up pair
- Exploit PoCs / vulnerability demos
- Changing `xmlBuf` field layout (kept compatible with historical `xmlBuffer` base)

## Enabling (optional, experimental)

Meson (OFF by default):

```bash
meson setup build -Dbounds-safety=enabled   # requires Clang with -fbounds-safety
```

CMake (OFF by default):

```bash
cmake -DLIBXML2_WITH_BOUNDS_SAFETY=ON ...
```

## Follow-up CLs (suggested order)

1. `xmlParserInput` clear pair: `cur` `XML_ENDED_BY(end)` (and/or `base`).
2. Audit `xmlBuf` shrink/grow paths for side-by-side updates of `content`/`size`
   when the option is ON (required by the bounds-safety programming model).
3. Consider documenting NUL byte (`size + 1` allocation) vs capacity annotation.
4. Annotate additional private buffers only after each pair is proven under
   `-fbounds-safety` builds.

## Upstream / AI policy gate

`README.md` → **Strict No LLM / No AI Policy**:

- No LLMs for issues
- No LLMs for patches / pull requests
- No LLMs for comments on the bug tracker

**AI gate: BAN** — this draft must not be opened as an upstream MR as-is if it
was produced with LLM assistance. Human rewrite / maintainer-approved exception
required before any GitLab MR.

## Author

Jeff <jeff@incrediblybased.co>

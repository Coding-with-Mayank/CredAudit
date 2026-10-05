# External tools: why they're not bundled, and how to get them

CredAudit shells out to a handful of well-established external security
tools rather than reimplementing them:

| Tool | Used for | Called from |
|---|---|---|
| Hydra (or Medusa/ncrack) | Online credential testing | `integrations/hydra.py`, `modules/online.py` |
| Hashcat (or John the Ripper) | Offline hash cracking | `modules/offline.py` |
| nuclei | Template-based vulnerability scanning | `integrations/nuclei.py` |

## Why these aren't pip dependencies

Three reasons, each independent of the others:

1. **They aren't Python packages.** They're compiled binaries (Hydra,
   Hashcat, John) or a standalone Go binary (nuclei), each with its own
   build system, platform-specific binaries, and, in Hashcat's case, GPU
   driver dependencies that a `pip install` has no way to satisfy
   correctly.
2. **Re-implementing them would make things worse, not better.**
   Hashcat's whole value is highly-optimized, GPU-accelerated guessing
   across dozens of hash formats; Hydra/Medusa/ncrack's is
   protocol-correct, well-tested client implementations for dozens of
   services. Reimplementing either inside this project, even partially,
   would mean shipping a strictly worse version of tools that are
   already mature, actively maintained, and — this matters — already
   understood and trusted by the security community that uses them. See
   the main README's own framing of this.
3. **Licensing.** These tools carry their own licenses (GPL in some
   cases), separate from this project's. Vendoring compiled binaries
   into a pip-installable wheel would tangle this project's packaging
   and distribution with license terms that don't apply to the rest of
   the codebase.

## Three ways to get them

### 1. Your OS package manager (simplest for local use)

```bash
# Debian / Kali / Ubuntu
sudo apt install hydra hashcat nuclei john

# macOS (Homebrew)
brew install hydra hashcat nuclei john-jumbo

# Arch
sudo pacman -S hydra hashcat nuclei john
```

### 2. The bundled Docker image (simplest for a clean, reproducible environment)

```bash
docker build -t credaudit .
docker run --rm -it -v "$PWD":/work -w /work credaudit \
  run --scope engagement.yaml --out ./out
```

The image is built on `kalilinux/kali-rolling` specifically because
that's where these tools are already packaged, tested, and kept
current — not because this is "a Kali tool" in any other sense.
`docker run --rm credaudit doctor` should report every external tool as
found inside the container with zero extra setup.

### 3. Check what you have right now

```bash
credaudit doctor
```

Prints which optional Python extras (`anthropic`, `fastapi`, etc.) and
which external tools are currently on `PATH`, with install hints for
whatever's missing. Run this first if a module unexpectedly reports a
tool as unavailable.

## What CredAudit does and doesn't do with these tools

CredAudit never auto-installs, auto-invokes without scope
authorization, or silently falls back to a weaker reimplementation when
one of these is missing — it reports the gap clearly (via `doctor`, or
at the point a module needs the tool and can't find it) instead of
working around it. The scope-gating and confirmation requirements in
`modules/online.py` and elsewhere apply identically no matter which
underlying tool (Hydra vs. Medusa vs. ncrack) actually gets invoked.

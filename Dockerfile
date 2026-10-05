# CredAudit, all-in-one: the Python package plus the external tools it
# deliberately does NOT vendor (see docs/external_tools.md for why
# Hydra/Hashcat/nuclei aren't pip dependencies). This image exists
# purely for convenience -- `credaudit doctor` inside it should report
# every external tool as found, with zero manual installation.
#
# Base: Kali Linux rolling. Not because this is a "Kali tool" in any
# special sense -- CredAudit is a plain Python package that happens to
# shell out to a few well-known external security tools when asked --
# but because Kali's repos are where hydra/hashcat/nuclei are already
# packaged, tested, and kept current, so building on it is less work
# and less drift than hand-compiling each one on a generic base image.
#
# Build:   docker build -t credaudit .
# Run:     docker run --rm -it -v "$PWD":/work -w /work credaudit run --scope engagement.yaml --out ./out
# Doctor:  docker run --rm credaudit doctor
# Serve:   docker run --rm -p 8000:8000 -e CREDAUDIT_JWT_SECRET=... credaudit serve --host 0.0.0.0

FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    hydra \
    hashcat \
    nuclei \
    john \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/credaudit
COPY pyproject.toml README.md ./
COPY credaudit ./credaudit

# Full-featured install: the whole point of this image is "nothing
# else to set up," so every optional extra comes along.
RUN pip install --no-cache-dir ".[all]"

# nuclei keeps its own template repository separate from the binary;
# fetch it once at build time so a fresh container doesn't need network
# access just to run a scan. (This itself is a network call made only
# during the image build, to nuclei's own project -- not at scan time,
# and not involving any engagement's actual targets.)
RUN nuclei -update-templates || true

WORKDIR /work
ENTRYPOINT ["credaudit"]
CMD ["doctor"]

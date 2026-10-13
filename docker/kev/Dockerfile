# kev-0.8b decision-model server (CPU) for the gateway's opt-in judge.
#
# Weights are NOT baked into the image: the entrypoint downloads them
# from HuggingFace on first boot into the /models named volume.
#
# kev.serve comes from upstream (Apache-2.0, github.com/jaredpalmer/kev),
# pinned to the commit this gateway's judge driver was verified against.
# It is installed as a dependency from upstream — no kev code is vendored
# or copied into the gateway repo.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    KEV_DTYPE=bf16

# curl: torch wheel download + container healthcheck.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /models /tmp/kev-build

# Non-root service user (issue #6; mirrors the gateway image's appuser).
RUN useradd --create-home --shell /usr/sbin/nologin kevuser

WORKDIR /srv/kev

# Pinned SHA-256 digests (issue #6): single source of truth, also
# sourced by the entrypoint for the first-boot HF downloads.
COPY docker/kev/artifact-digests.env /usr/local/etc/kev/artifact-digests.env

# setuptools first: the torch CPU index does not carry it and bare
# venvs/pip installs stall without it (build-log M0 lesson).
RUN pip install --no-cache-dir setuptools

# CPU torch WITHOUT the resolver (pip backtracks 16+ min on the bare
# spec): download the wheel directly, verify its pinned SHA-256
# (issue #6 — abort the build on mismatch), then install the file.
# TMPDIR points off the small /tmp so the download cannot die with
# ENOSPC.
RUN set -a; . /usr/local/etc/kev/artifact-digests.env; set +a; \
    curl -o /tmp/kev-build/torch-2.8.0+cpu-cp312-cp312-manylinux_2_28_x86_64.whl \
        https://download.pytorch.org/whl/cpu/torch-2.8.0%2Bcpu-cp312-cp312-manylinux_2_28_x86_64.whl \
    && echo "${TORCH_WHEEL_SHA256}  /tmp/kev-build/torch-2.8.0+cpu-cp312-cp312-manylinux_2_28_x86_64.whl" \
        | sha256sum -c - \
    && TMPDIR=/tmp/kev-build pip install --no-cache-dir \
        /tmp/kev-build/torch-2.8.0+cpu-cp312-cp312-manylinux_2_28_x86_64.whl \
    && rm /tmp/kev-build/torch-2.8.0+cpu-cp312-cp312-manylinux_2_28_x86_64.whl

# Pinned to the kev repo's uv.lock (avoids resolver backtracking).
RUN pip install --no-cache-dir \
        "transformers==5.17.0" "peft==0.21.0" "accelerate==1.15.0" \
        "tokenizers==0.23.2" "scikit-learn" "numpy>=2.5.3" \
        "huggingface-hub==1.32.0" "safetensors==0.8.0" \
        "fastapi==0.141.1" "uvicorn==0.53.0" "pydantic==2.13.5"

# kev.serve, pinned to the verified commit (see build-log.md: the wire
# corrections were made against this checkout). The tarball's SHA-256
# is pinned in artifact-digests.env and verified before install
# (issue #6 — abort the build on mismatch).
ARG KEV_COMMIT=85ccf56a0afb952323c621055b02876e8498d60c
RUN set -a; . /usr/local/etc/kev/artifact-digests.env; set +a; \
    curl -o /tmp/kev-build/kev.tar.gz \
        "https://github.com/jaredpalmer/kev/archive/${KEV_COMMIT}.tar.gz" \
    && echo "${KEV_TARBALL_SHA256}  /tmp/kev-build/kev.tar.gz" \
        | sha256sum -c - \
    && pip install --no-cache-dir --no-deps /tmp/kev-build/kev.tar.gz \
    && rm /tmp/kev-build/kev.tar.gz

COPY docker/kev/entrypoint.sh /usr/local/bin/kev-entrypoint.sh
RUN chmod +x /usr/local/bin/kev-entrypoint.sh

# /models is a named volume at runtime; chown now so a FRESH volume
# inherits kevuser ownership (Docker copies image-path ownership into
# new volumes). The entrypoint (running as kevuser) downloads weights
# and patches head.pt under /models.
RUN chown -R kevuser:kevuser /models /home/kevuser /srv/kev

VOLUME /models
EXPOSE 8009
USER kevuser
ENTRYPOINT ["/usr/local/bin/kev-entrypoint.sh"]

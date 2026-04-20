# Multi-stage image for mception. Runs the stdio MCP server on container start.
# Size-optimized: only runtime deps in the final layer.

FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir --upgrade pip build \
    && python -m build --wheel --outdir /wheels .

FROM python:3.12-slim AS runtime

# No root in the runtime container.
RUN groupadd --system mception && useradd --system --gid mception --home /home/mception mception \
    && mkdir -p /home/mception && chown mception:mception /home/mception

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl \
    && rm -rf /wheels

USER mception
ENV MCEPTION_DATA_DIR=/home/mception/.mception

# stdio transport: the MCP client connects on stdin/stdout.
ENTRYPOINT ["mception"]

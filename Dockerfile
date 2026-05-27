FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY mcp_memory_lookup.py .
COPY store_vfs.py .
COPY store_vfs_schema.py .
COPY store_vfs_effects_new.py .
COPY scorer.py .
COPY bm25.py .
COPY config.py .
COPY utils.py .
COPY schema.py .

RUN pip install --no-cache-dir mcp>=1.0

ENTRYPOINT ["python", "mcp_memory_lookup.py"]

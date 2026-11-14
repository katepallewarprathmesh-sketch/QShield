# QSHIELD Workbench — self-hostable container (offline by default).
#   docker build -t qshield .
#   docker run --rm -p 8765:8765 qshield        # http://localhost:8765
FROM python:3.12-slim
WORKDIR /app

# Install just the runtime (no [formal]/[ml]: keep the image lean;
# unitary compare works; ZX needs `pip install '.[formal]'`).
COPY pyproject.toml LICENSE README.md ./
COPY src ./src
# keep the bundled corpus so Policy Studio works inside the image
COPY tests/fixtures ./tests/fixtures

RUN pip install --no-cache-dir . && useradd -m app
ENV QSHIELD_FIXTURES_DIR=/app/tests/fixtures
USER app
EXPOSE 8765
CMD ["qshield", "ui", "--host", "0.0.0.0", "--port", "8765"]

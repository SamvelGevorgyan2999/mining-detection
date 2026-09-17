FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml README.md ./
COPY miningguard ./miningguard
RUN pip install --no-cache-dir --no-deps .

EXPOSE 8000

# The collector needs host PID and network namespaces to see anything useful;
# see docker-compose.yml for how the agent service is wired.
CMD ["uvicorn", "miningguard.api:app", "--host", "0.0.0.0", "--port", "8000"]



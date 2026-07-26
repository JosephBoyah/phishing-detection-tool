FROM python:3.11-slim

WORKDIR /app

# system deps for python-whois / ssl
RUN apt-get update && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=5000
EXPOSE 5000

# Safe Browsing key is passed at runtime: -e SAFE_BROWSING_API_KEY=...
CMD ["python", "app/app.py"]

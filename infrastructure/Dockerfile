# Dockerfile
# TEST HARNESS: This file intentionally contains hardcoded secrets in ENV instructions
# for secrets detection tool benchmarking. All credentials are FAKE.
# See secrets-manifest.csv for ground truth.

FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# --- MANIFEST ID 93 ---
# AWS credentials baked into Docker image via ENV
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7FAKDKR1
ENV AWS_SECRET_ACCESS_KEY=DockerFakeSecretKey/bPxRfiCYEXAMPLEKEY/VALUE

# --- MANIFEST ID 94 ---
# Database credentials in Docker ENV
ENV DATABASE_URL=postgresql://dockeruser:DockerDbP@ssword!999@db.internal:5432/appdb

# --- MANIFEST ID 95 ---
# Stripe key in Docker ENV
ENV STRIPE_SECRET_KEY=sk_live_51DockerFakeStripeKeyABCDEFGHIJKLMNOPQRSTUVWXYZ01234567

# --- MANIFEST ID 96 ---
# JWT secret in Docker ENV
ENV JWT_SECRET=docker_jwt_secret_key_hardcoded_in_dockerfile_bad_practice_2024

# Not secrets
ENV PORT=8080
ENV LOG_LEVEL=info
ENV PYTHONPATH=/app

EXPOSE 8080
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]

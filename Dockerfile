# FortGuard test server. One process on purpose: sessions and devices are kept in memory,
# so several workers would each see only part of the data.
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt requirements-prod.txt ./
RUN pip install --no-cache-dir -r requirements-prod.txt
COPY fortguard ./fortguard
EXPOSE 8080
CMD ["sh", "-c", "gunicorn 'fortguard.app:production_app()' --workers 1 --threads 16 --bind 0.0.0.0:${PORT:-8080} --access-logfile -"]

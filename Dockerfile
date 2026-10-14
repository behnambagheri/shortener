FROM node:24-bookworm-slim AS frontend
WORKDIR /shortener
COPY approved_domains.json ./
COPY templates ./templates
COPY ui ./ui
COPY cloudflare ./cloudflare
RUN cd cloudflare && npm ci && npm run build

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /shortener
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . ./
COPY --from=frontend /shortener/public ./public
COPY start /usr/local/bin/start
RUN chmod +x /usr/local/bin/start
CMD ["start"]

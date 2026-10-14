# syntax=docker/dockerfile:1
# The bundled server is platform-independent JavaScript, so build once on the native platform.
FROM --platform=$BUILDPLATFORM node:24-bookworm-slim AS build
WORKDIR /build
COPY package.json package-lock.json .npmrc ./
RUN npm ci --no-audit --no-fund
COPY approved_domains.json ./
COPY templates/ ./templates/
COPY ui/ ./ui/
COPY src/ ./src/
COPY server/ ./server/
COPY migrations/ ./migrations/
COPY scripts/build.mjs ./scripts/build.mjs
RUN npm run build

FROM node:24-alpine
ARG BUILD_REVISION=development
ENV NODE_ENV=production DEPLOYMENT_SHA=$BUILD_REVISION PORT=8080 DATA_DIR=/var/lib/shortener
RUN mkdir -p /app /var/lib/shortener && chown 10001:10001 /var/lib/shortener
COPY --from=build /build/dist/server.mjs /app/server.mjs
COPY ui/fonts/OFL.txt /usr/share/doc/shortener/SpaceGrotesk-OFL.txt
USER 10001:10001
WORKDIR /app
VOLUME ["/var/lib/shortener"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD wget -q -O /dev/null http://127.0.0.1:8080/.well-known/health || exit 1
ENTRYPOINT ["node", "--disable-warning=ExperimentalWarning", "/app/server.mjs"]

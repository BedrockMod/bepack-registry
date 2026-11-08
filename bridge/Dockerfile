FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY lib ./lib
COPY bridge ./bridge
RUN addgroup -S bridge && adduser -S bridge -G bridge && mkdir -p /data && chown -R bridge:bridge /data /app
USER bridge
ENV BRIDGE_DATA_DIR=/data PORT=8787 HOST=0.0.0.0
EXPOSE 8787
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8787/healthz >/dev/null || exit 1
CMD ["node", "bridge/main.mjs"]

# Packed from THIS repo only. Do not ADD remote URLs. Build with --network=none --pull=false.
# The CT never talks to a registry: it docker-load's the tar this file produces.
FROM node:22-bookworm-slim
WORKDIR /app
COPY core/nmzp.mjs /app/nmzp.mjs
COPY src/lib/monitor /app/monitor
RUN chmod 0755 /app/nmzp.mjs \
  && ln -s /app/nmzp.mjs /usr/local/bin/nmzp
ENV NODE_OPTIONS=--experimental-strip-types
EXPOSE 8787
CMD ["node", "--experimental-strip-types", "/app/nmzp.mjs", "serve"]

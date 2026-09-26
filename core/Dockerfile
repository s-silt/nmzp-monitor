# Packed from THIS repo only. Do not ADD remote URLs. Build with --network=none --pull=false.
# Build context is the packed runtime directory (.pack/nmzp), not the git checkout.
# The CT never talks to a registry: it docker-load's the tar this file produces.
FROM node:24-bookworm-slim

RUN groupadd --system nmzp \
 && useradd --system --gid nmzp --no-create-home --shell /usr/sbin/nologin nmzp \
 && mkdir -p /var/lib/nmzp \
 && chown nmzp:nmzp /var/lib/nmzp \
 && chmod 0700 /var/lib/nmzp

COPY . /opt/nmzp/

ENV NODE_OPTIONS=--experimental-strip-types
ENV NMZP_BIND=0.0.0.0
ENV NMZP_PORT=8787
ENV NMZP_DATA=/var/lib/nmzp

USER nmzp
WORKDIR /opt/nmzp
EXPOSE 8787
CMD ["/usr/local/bin/node", "--experimental-strip-types", "/opt/nmzp/nmzp.mjs", "serve"]

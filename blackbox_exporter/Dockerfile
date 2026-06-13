FROM alpine:3.24 AS builder

RUN apk add --no-cache gettext

FROM prom/blackbox-exporter:v0.28.0

COPY --from=builder /usr/bin/envsubst /usr/bin/envsubst
COPY --from=builder /lib/ld-musl-x86_64.so.1 /lib/ld-musl-x86_64.so.1
COPY --from=builder /usr/lib/libintl.so.8 /usr/lib/libintl.so.8

COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["--config.file=/etc/blackbox_exporter/config.yml"]

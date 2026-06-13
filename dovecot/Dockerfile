FROM alpine:3.24

# renovate: datasource=github-releases depName=tianon/gosu versioning=semver-coerced extractVersion=^(?<version>.*)$
ARG GOSU_VERSION=1.19

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Add groups and users before installing Dovecot to not break compatibility
RUN addgroup -g 5000 vmail \
  && addgroup -g 401 dovecot \
  && addgroup -g 402 dovenull \
  && sed -i "s/999/99/" /etc/group \
  && addgroup -g 999 sogo \
  && addgroup nobody sogo \
  && adduser -D -u 5000 -G vmail -h /var/vmail vmail \
  && adduser -D -G dovecot -u 401 -h /dev/null -s /sbin/nologin dovecot \
  && adduser -D -G dovenull -u 402 -h /dev/null -s /sbin/nologin dovenull \
  && apk add --no-cache --update \
  bash \
  bind-tools \
  findutils \
  envsubst \
  ca-certificates \
  curl \
  coreutils \
  jq \
  lua \
  lua-cjson \
  lua-socket \
  lua-sql-mysql \
  lua5.3-sql-mysql \
  icu-data-full \
  mariadb-connector-c \
  gcompat \
  mariadb-client \
  perl \
  perl-ntlm \
  perl-cgi \
  perl-crypt-openssl-rsa \
  perl-utils \
  perl-crypt-ssleay \
  perl-data-uniqid \
  perl-dbd-mysql \
  perl-dbi \
  perl-digest-hmac \
  perl-dist-checkconflicts \
  perl-encode-imaputf7 \
  perl-file-copy-recursive \
  perl-file-tail \
  perl-io-socket-inet6 \
  perl-io-gzip \
  perl-io-socket-ssl \
  perl-io-tee \
  perl-ipc-run \
  perl-json-webtoken \
  perl-mail-imapclient \
  perl-module-implementation \
  perl-module-scandeps \
  perl-net-ssleay \
  perl-package-stash \
  perl-package-stash-xs \
  perl-par-packer \
  perl-parse-recdescent \
  perl-lockfile-simple \
  libproc2 \
  perl-readonly \
  perl-regexp-common \
  perl-sys-meminfo \
  perl-term-readkey \
  perl-test-deep \
  perl-test-fatal \
  perl-test-mockobject \
  perl-test-mock-guard \
  perl-test-pod \
  perl-test-requires \
  perl-test-simple \
  perl-test-warn \
  perl-try-tiny \
  perl-unicode-string \
  perl-proc-processtable \
  perl-app-cpanminus \
  procps \
  python3 \
  py3-mysqlclient \
  py3-html2text \
  py3-jinja2 \
  py3-redis \
  redis \
  syslog-ng \
  syslog-ng-redis \
  syslog-ng-json \
  supervisor \
  tzdata \
  wget \
  dovecot \
  dovecot-dev \
  dovecot-lmtpd \
  dovecot-lua \
  dovecot-ldap \
  dovecot-mysql \
  dovecot-sql \
  dovecot-submissiond \
  dovecot-pigeonhole-plugin \
  dovecot-pop3d \
  dovecot-fts-flatcurve \
  && arch=$(arch | sed s/aarch64/arm64/ | sed s/x86_64/amd64/) \
  && wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$arch" \
  && chmod +x /usr/local/bin/gosu \
  && gosu nobody true

COPY syslog-ng.conf \
  syslog-ng-redis_slave.conf \
  /etc/syslog-ng/
COPY supervisord.conf \
  /etc/supervisor/
COPY report-spam.sieve \
  report-ham.sieve \
  rspamd-pipe-ham \
  rspamd-pipe-spam \
  /usr/lib/dovecot/sieve/
COPY trim_logs.sh \
  clean_q_aged.sh \
  imapsync \
  imapsync_runner.pl \
  sa-rules.sh \
  maildir_gc.sh \
  quarantine_notify.py \
  quota_notify.py \
  repl_health.sh \
  optimize-fts.sh \
  /usr/local/bin/
COPY stop-supervisor.sh \
  /usr/local/sbin/

COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]

ARG DEBIAN_RELEASE=trixie
FROM debian:${DEBIAN_RELEASE}-slim

ARG DEBIAN_RELEASE
ARG DEBIAN_FRONTEND=noninteractive
ARG SOGO_DEBIAN_REPOSITORY=http://www.axis.cz/linux/debian
# renovate: datasource=github-releases depName=tianon/gosu versioning=semver-coerced extractVersion=^(?<version>.*)$
ARG GOSU_VERSION=1.20
ENV LC_ALL=C

# Prerequisites
RUN echo "Building from repository $SOGO_DEBIAN_REPOSITORY" \
  && apt-get update && apt-get install -y --no-install-recommends \
  apt-transport-https \
  ca-certificates \
  gettext \
  gnupg \
  mariadb-client \
  rsync \
  supervisor \
  syslog-ng \
  syslog-ng-core \
  syslog-ng-mod-redis \
  dirmngr \
  netcat-traditional \
  psmisc \
  wget \
  patch \
  && dpkgArch="$(dpkg --print-architecture | awk -F- '{ print $NF }')" \
  && wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch" \
  && chmod +x /usr/local/bin/gosu \
  && gosu nobody true \
  && mkdir /usr/share/doc/sogo \
  && touch /usr/share/doc/sogo/empty.sh \
  && wget http://www.axis.cz/linux/debian/axis-archive-keyring.deb -O /tmp/axis-archive-keyring.deb \
  && apt install -y /tmp/axis-archive-keyring.deb \
  && echo "deb [trusted=yes] ${SOGO_DEBIAN_REPOSITORY} ${DEBIAN_RELEASE} sogo-v5" > /etc/apt/sources.list.d/sogo.list \
  && apt-get update && apt-get install -y --no-install-recommends \
    sogo \
    sogo-activesync \
  && apt-get autoclean \
  && rm -rf /var/lib/apt/lists/* \
  && touch /etc/default/locale

COPY bootstrap-sogo.sh \
  acl.diff \
  /
COPY supervisord.conf \
  /etc/supervisor/
COPY syslog-ng.conf \
  syslog-ng-redis_slave.conf \
  /etc/syslog-ng/
COPY stop-supervisor.sh \
  /usr/local/sbin/

COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]

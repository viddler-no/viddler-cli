ARG JITSI_REPO=jitsi
FROM ${JITSI_REPO}/base

# Instead of getting jitsi-meet-web package, we build into this
RUN \
	apt-dpkg-wrap apt-get update && \
	apt-dpkg-wrap apt-get install -y cron nginx-extras && \
	apt-dpkg-wrap apt-get install -y -t stretch-backports certbot && \
	apt-cleanup && \
	rm -f /etc/nginx/conf.d/default.conf && \
	rm -f /usr/share/jitsi-meet/interface_config.js

COPY rootfs/ /

COPY meet/ /usr/share/jitsi-meet/

EXPOSE 80 443

VOLUME ["/config", "/etc/letsencrypt"]

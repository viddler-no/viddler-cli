# !! Currently not in use
FROM ubuntu:bionic
RUN apt-get update

ADD xdebug-proxy /usr/local/bin/xdebug-proxy

# To not run as root
RUN useradd -K MAIL_DIR=/dev/null run-user

RUN chown run-user:run-user /usr/local/bin/xdebug-proxy && \
    chmod +x /usr/local/bin/xdebug-proxy

USER run-user

EXPOSE 3308

ENTRYPOINT ["/usr/local/bin/xdebug-proxy"]
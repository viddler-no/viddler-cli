# todo:
# https://shaneutt.com/blog/rust-fast-small-docker-image-builds/

# going for a minimal ssh-able linux compatible with server
# environment, to build server intended binaries.

FROM ubuntu:bionic

RUN apt-get update && apt-get install -y --no-install-recommends apt-utils

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
	pkg-config \
	libssl-dev \
	libssl1.1 \
	ca-certificates

RUN apt-get update && apt-get install -y \
	curl \
	apt-utils \
	openssh-server

RUN mkdir /var/run/sshd
# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd
# todo: Could only allow from host ip, see wp-dev for getting ip

# todo: see further comments in wp-cli dockerfile
RUN echo 'www-data:www-data' | chpasswd && \
	usermod --shell /bin/bash www-data

# todo: For simplicity, using var/www which is the default
# home dir of www-data
RUN mkdir -p /var/www && chmod 755 /var/www && chown www-data:www-data /var/www
VOLUME /var/www

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
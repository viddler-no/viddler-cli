FROM ubuntu:bionic

RUN mkdir /db && chown www-data:www-data /db
VOLUME /db

ADD assets /var/lib/log_server/assets
RUN chown -R www-data:www-data /var/lib/log_server/assets

ADD log_server /usr/local/bin/log_server
RUN chown www-data /usr/local/bin/log_server && \
    chmod +x /usr/local/bin/log_server

USER www-data
EXPOSE 7006
CMD [ "/usr/local/bin/log_server" ]
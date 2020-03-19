#FROM php:7.3-apache
FROM wordpress:5-php7.3-apache
# vagrant group is 1000, adding to
# enable access to mounted volumes
#RUN groupadd --gid 1000 vagrant && usermod -a -G vagrant www-data

# Xdebug and pecl
RUN pecl channel-update pecl.php.net && \
    pecl install xdebug

# To locate host ip, creating host.docker.internal
# todo: This might become part of docker, but is missing for linux
RUN apt-get update && apt-get install -y iproute2
# todo: Remove apt package files?

# Add to php ini, todo: automate correct .so
RUN { \
        echo "zend_extension=/usr/local/lib/php/extensions/no-debug-non-zts-20180731/xdebug.so"; \
        echo "[XDebug]"; \
        echo "xdebug.remote_enable = 1"; \
        echo "xdebug.remote_autostart = 1"; \
        echo "xdebug.remote_port = 9001"; \
        #echo "xdebug.remote_host = host.docker.internal"; \
        # todo: Hopefully linux will also get support for host.docker.internal
        echo "xdebug.remote_host = 172.17.0.1"; \
        echo "xdebug.remote_log=/tmp/xdebug_remote.log"; \
    } > /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini

COPY custom-entrypoint.sh /usr/local/bin
RUN chmod +x /usr/local/bin/custom-entrypoint.sh

ENTRYPOINT ["custom-entrypoint.sh"]
CMD ["apache2-foreground"]
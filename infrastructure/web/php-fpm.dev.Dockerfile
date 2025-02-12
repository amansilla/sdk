ARG SDK_VERSION

FROM php:8.0-fpm-alpine

ARG XDEBUG_PORT=9003

RUN apk --no-cache add autoconf g++ make \
    && pecl install xdebug \
    && docker-php-ext-enable xdebug \
    && rm -rf /tmp/pear; apk del autoconf g++ make;

COPY infrastructure/debug/php/69-xdebug.ini /usr/local/etc/php/conf.d/69-xdebug.ini

RUN cp /usr/local/etc/php/php.ini-development /usr/local/etc/php/php.ini

ARG USER_UID=1000
ARG GROUP_UID=1000

RUN deluser www-data && addgroup -g ${GROUP_UID} -S www-data && adduser -u ${USER_UID} -D -S -G www-data www-data

CMD ["php-fpm"]

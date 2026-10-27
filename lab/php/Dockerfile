FROM php:8.3-fpm-alpine

RUN apk add --no-cache bash coreutils findutils grep tar \
    && docker-php-ext-install pdo_mysql

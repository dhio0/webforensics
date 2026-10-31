FROM composer@sha256:5248900ab8b5f7f880c2d62180e40960cd87f60149ec9a1abfd62ac72a02577c AS composer

FROM php@sha256:a935f4a5717427519337269d5d1c89968cc27ab84d1c8d5d7b5363672d800cd5

RUN apt-get update \
    && apt-get install -y --no-install-recommends libfreetype6-dev libicu-dev libjpeg62-turbo-dev libpng-dev libpq-dev libzip-dev unzip \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j"$(nproc)" gd intl mysqli pdo_mysql pdo_pgsql pgsql zip \
    && a2enmod rewrite headers \
    && printf '<Directory /var/www/html>\nAllowOverride All\n</Directory>\n' > /etc/apache2/conf-available/phpmyfaq.conf \
    && a2enconf phpmyfaq \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer /usr/bin/composer /usr/local/bin/composer

ADD --checksum=sha256:282b638d7ecda25d6a803d16d9865c6b8aa0516ec9ed6d24bfadabdc6800d05f \
    https://codeload.github.com/thorsten/phpMyFAQ/zip/refs/tags/3.2.5 /tmp/phpmyfaq.zip

RUN unzip -q /tmp/phpmyfaq.zip -d /opt \
    && cd /opt/phpMyFAQ-3.2.5 \
    && composer install --no-dev --no-interaction --prefer-dist --classmap-authoritative \
    && cp -a phpmyfaq/. /var/www/html/ \
    && chown -R www-data:www-data /var/www/html \
    && rm -rf /opt/phpMyFAQ-3.2.5 /tmp/phpmyfaq.zip

COPY scripts/collect.sh /opt/collect.sh

ENV TZ=UTC
WORKDIR /var/www/html

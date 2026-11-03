FROM php@sha256:a935f4a5717427519337269d5d1c89968cc27ab84d1c8d5d7b5363672d800cd5

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpng-dev unzip \
    && docker-php-ext-install -j"$(nproc)" gd mysqli pdo_mysql \
    && a2enmod rewrite headers \
    && printf '<Directory /var/www/html>\nAllowOverride All\n</Directory>\n' > /etc/apache2/conf-available/dvwa.conf \
    && a2enconf dvwa \
    && rm -rf /var/lib/apt/lists/*

ADD --checksum=sha256:4bd1cb5dda6bdb889055bf0bcdbaf8fd9562ac358bb61918f3c0cb5199a76258 \
    https://codeload.github.com/digininja/DVWA/zip/a1978a2fed195acd093010af6395f86a281537ca /tmp/dvwa.zip

RUN unzip -q /tmp/dvwa.zip -d /opt \
    && cp -a /opt/DVWA-a1978a2fed195acd093010af6395f86a281537ca/. /var/www/html/ \
    && cp /var/www/html/config/config.inc.php.dist /var/www/html/config/config.inc.php \
    && chown -R www-data:www-data /var/www/html \
    && rm -rf /opt/DVWA-a1978a2fed195acd093010af6395f86a281537ca /tmp/dvwa.zip

COPY scripts/collect.sh /opt/collect.sh

ENV TZ=UTC
WORKDIR /var/www/html

FROM python@sha256:70bda1e795ded2a684ef9815955e05829b14ee5bb5c3eb2a940648e88f10fce9

RUN python -m pip install --no-cache-dir requests==2.32.4 \
    && apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates build-essential libssl-dev libidn2-dev \
    && git clone https://github.com/epinna/weevely3.git /opt/weevely3 \
    && git -C /opt/weevely3 checkout 3d62e889871a62a344365b6a2d02b35c5ac1e946 \
    && python -m pip install --no-cache-dir /opt/weevely3 \
    && git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && git -C /opt/sqlmap checkout c42ebd7acf47c88b6407995dd9842a2eb5d6534d \
    && git clone https://github.com/commixproject/commix.git /opt/commix \
    && git -C /opt/commix checkout 625c0c46e4257c457774e39bd896307397eaab03 \
    && git clone https://github.com/vanhauser-thc/thc-hydra.git /opt/hydra \
    && git -C /opt/hydra checkout a247d063e35f24218f55cc3c705e20073d1379eb \
    && cd /opt/hydra && ./configure --disable-xhydra && make -j2 && make install \
    && cd /opt \
    && apt-get purge -y --auto-remove git build-essential libssl-dev libidn2-dev \
    && rm -rf /var/lib/apt/lists/* /opt/weevely3/.git /opt/sqlmap/.git /opt/commix/.git /opt/hydra/.git

WORKDIR /opt
CMD ["sleep", "infinity"]

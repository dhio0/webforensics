FROM python@sha256:70bda1e795ded2a684ef9815955e05829b14ee5bb5c3eb2a940648e88f10fce9

RUN python -m pip install --no-cache-dir requests==2.32.4 \
    && apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && git clone https://github.com/epinna/weevely3.git /opt/weevely3 \
    && git -C /opt/weevely3 checkout 3d62e889871a62a344365b6a2d02b35c5ac1e946 \
    && python -m pip install --no-cache-dir /opt/weevely3 \
    && apt-get purge -y --auto-remove git \
    && rm -rf /var/lib/apt/lists/* /opt/weevely3/.git

WORKDIR /opt
CMD ["sleep", "infinity"]

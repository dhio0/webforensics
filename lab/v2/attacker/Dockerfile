FROM python@sha256:94a8fee35252d06ab75856f15f12c7bae67b10e8a6da93c7fded82b2610926cd

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

FROM python@sha256:94a8fee35252d06ab75856f15f12c7bae67b10e8a6da93c7fded82b2610926cd

RUN python -m pip install --no-cache-dir cryptography==50.0.2
COPY lab/v2/collect.py lab/v2/crypto.py /opt/v2/
WORKDIR /opt/v2
CMD ["sleep", "infinity"]

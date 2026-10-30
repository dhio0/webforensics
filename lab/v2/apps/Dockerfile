FROM python@sha256:94a8fee35252d06ab75856f15f12c7bae67b10e8a6da93c7fded82b2610926cd AS plugin_unpack

ADD --checksum=sha256:f70dd0e72d030795639e3c59e4a0c73005cabf07e1c91efaa34d0808a5995c9d \
    https://downloads.wordpress.org/plugin/wp-file-manager.6.0.zip /tmp/plugin.zip
RUN python -c "import io,zipfile; z=zipfile.ZipFile('/tmp/plugin.zip'); p=zipfile.ZipFile(io.BytesIO(z.read('wp-file-manager/wp-file-manager-6.O.zip'))); p.extractall('/tmp/plugins')"

FROM wordpress@sha256:cf7c7a9c9cc8614a7357dac77d401612c67af5e0ab1ab19e0777f643af3d3a3c
COPY --from=plugin_unpack /tmp/plugins/wp-file-manager /usr/src/wordpress/wp-content/plugins/wp-file-manager
COPY scripts/collect.sh /opt/collect.sh

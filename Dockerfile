# busbar container image: FROM scratch, because the binary is the whole product.
# Static musl binaries are built in CI (see .github/workflows/docker.yml) and copied
# in per-arch; CA roots are compiled into the binary (webpki-roots), so no /etc/ssl
# is needed. The vetted provider catalog ships inside the image as the default.
#
# Run:
#   docker run -d -p 8080:8080 \
#     -e ANTHROPIC_KEY \
#     -v "$PWD/config.yaml:/etc/busbar/config.yaml:ro" \
#     getbusbar/busbar
#
# Governance (optional) needs a writable volume for the SQLite file, e.g.
#   -v busbar-data:/var/lib/busbar   with governance.db_path: /var/lib/busbar/governance.db
FROM scratch

ARG TARGETARCH
COPY binaries/${TARGETARCH}/busbar /busbar
COPY providers.yaml /etc/busbar/providers.yaml

ENV BUSBAR_PROVIDERS=/etc/busbar/providers.yaml \
    BUSBAR_CONFIG=/etc/busbar/config.yaml

EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/busbar"]

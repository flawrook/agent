# The agent's container image, for cluster mode: the release's own static binary on distroless, as user 65532.
# The build context is a folder holding flawrook-agent-linux-amd64 and -arm64 (dist/release, or the release's
# downloaded files in .github/workflows/release-sign.yml), so each platform takes its binary without emulation:
#   docker buildx build --platform linux/amd64,linux/arm64 -f packaging/Dockerfile dist/release
# The base is pinned by its index digest (static-debian13:nonroot, pushed 2026-10-31).
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
ARG TARGETARCH
ARG VERSION=dev
# The source label also links the package on ghcr.io to the repository.
LABEL org.opencontainers.image.title="FlawRook agent" \
      org.opencontainers.image.source="https://github.com/flawrook/agent" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"
COPY --chmod=0755 flawrook-agent-linux-${TARGETARCH} /usr/bin/flawrook-agent
# The image sets no HOME, and Syft looks the home directory up when it's unset (0.2.0's systemd 237 hang).
ENV HOME=/home/nonroot
USER 65532:65532
ENTRYPOINT ["/usr/bin/flawrook-agent"]

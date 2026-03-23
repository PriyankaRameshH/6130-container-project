FROM debian:bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential clang llvm make pkg-config libbpf-dev libelf-dev zlib1g-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN make all

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libbpf1 libelf1 zlib1g && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /src/bin/detector /app/detector
COPY --from=build /src/internal/bpf/escape_detector.bpf.o /app/escape_detector.bpf.o
COPY --from=build /src/examples/policy.yaml /app/policy.yaml

ENTRYPOINT ["/app/detector"]
CMD ["-bpf-object", "/app/escape_detector.bpf.o", "-policy", "/app/policy.yaml", "-json"]

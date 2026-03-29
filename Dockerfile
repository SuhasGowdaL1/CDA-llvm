FROM alpine:3.19 AS base-deps

RUN apk add --no-cache \
    bash \
    cmake \
    ninja \
    llvm17-dev \
    clang17-dev \
    clang17-libs \
    clang17-static \
    llvm17-gtest \
    llvm17-static \
    libffi-dev \
    libxml2-dev \
    zlib-dev \
    zstd-dev

WORKDIR /work
ENTRYPOINT ["/bin/sh"]

FROM base-deps AS linux-deps

RUN apk add --no-cache \
    build-base \
    libstdc++

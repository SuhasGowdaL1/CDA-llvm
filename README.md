# C CFG Generator (LibTooling)

This project provides a C++ binary that parses C files and generates control-flow graphs in Graphviz DOT format using Clang's CFG APIs.

## What It Produces

- `cfg_generator`: main CLI binary (C++ implementation, C input processing).
- DOT output for each function definition in input C file(s).

## Requirements

- LLVM/Clang 17 development packages with LibTooling.
- CMake 3.20+.
- A C toolchain.

## Build (Linux)

```sh
cmake -S . -B build-linux -DCMAKE_BUILD_TYPE=Release -DCFGGEN_BUILD_STATIC_LINUX=OFF
cmake --build build-linux -j
```

If full static linking is not available in your distro packages, disable it:

```sh
cmake -S . -B build-linux -DCMAKE_BUILD_TYPE=Release -DCFGGEN_BUILD_STATIC_LINUX=OFF
cmake --build build-linux -j
```

## Run

Direct binary:

```sh
./build-linux/cfg_generator -o out/sample.dot examples/sample.c -- -I. -DTEST=1
```

Wrapper script:

```sh
chmod +x scripts/generate_cfg.sh
scripts/generate_cfg.sh examples/sample.c out/sample.dot
```

Filter a single function:

```sh
./build-linux/cfg_generator -function classify -o out/complex.dot examples/complex_flow.c --
```

## Docker (Linux)

The Docker setup is dependency-only and Linux-only.

### Exact Steps: Build and Run with Docker

1. Build the Linux dependency image once:

```sh
scripts/build_linux_binary_docker.sh --build-image
```

2. Build the Linux binary using the stored image:

```sh
scripts/build_linux_binary_docker.sh
```

3. Create output directory:

```sh
mkdir -p out
```

4. Run the generated binary inside the Docker image:

```sh
docker run --rm -v "$PWD:/work" -w /work cfggen:linux-build-deps \
	-lc './build-linux/cfg_generator -o out/sample.dot examples/sample.c -- -I. -DTEST=1'
```

5. Verify output:

```sh
ls -l out/sample.dot
```

### Alternative Commands

Build Linux binary from Docker (reuses image if already available):

```sh
scripts/build_linux_binary_docker.sh
```

Build dependency image once (if you have not built it yet):

```sh
scripts/build_linux_binary_docker.sh --build-image
```

Build and store the Linux dependency image as a tar archive for later reuse:

```sh
scripts/build_and_store_docker_images.sh
```

Custom output directory for saved archives:

```sh
scripts/build_and_store_docker_images.sh ./artifacts/docker-images
```

Restore saved images later:

```sh
docker load -i ./docker-images/linux-deps.tar
```

Optional: auto-build only when image is missing:

```sh
CFGGEN_AUTO_BUILD=1 scripts/build_linux_binary_docker.sh
```

Docker helper script:

- `scripts/build_linux_binary_docker.sh`
- `scripts/build_and_store_docker_images.sh`

## Exit Codes

- `0`: success with at least one function CFG emitted.
- `1`: output file errors or runtime issues.
- `2`: command-line parsing errors.
- `3`: no function definitions found in parsed input.

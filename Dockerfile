# portview as a container image.
#
# Read this before using it: a container gets its own network and PID
# namespaces, so portview running inside one sees *the container's* ports and
# processes — which is to say, almost nothing. That is not a bug in portview;
# it is what namespaces are for. The demo recordings in demo/ rely on exactly
# this behaviour to isolate themselves.
#
# To inspect the host, share its namespaces:
#
#   docker run --rm -i --network host --pid host portview
#
# Without --network host the port list is empty. Without --pid host the ports
# resolve but the processes behind them do not.
#
# For everyday use, install the binary instead — it is ~1 MB with no runtime
# dependencies:
#
#   cargo install portview
#   brew install mapika/tap/portview

FROM rust:alpine AS builder

# The libc crate needs a C toolchain against musl.
RUN apk add --no-cache musl-dev

WORKDIR /src
COPY . .

# --locked so the image matches the committed Cargo.lock rather than resolving
# fresh dependencies at build time.
RUN cargo build --release --locked

FROM alpine:3

# procps is not required: portview reads /proc directly rather than shelling
# out to ps, ss, or lsof.
COPY --from=builder /src/target/release/portview /usr/local/bin/portview

# Defaults to the MCP server, which is the usual reason to run this in a
# container. Override for the CLI:
#
#   docker run --rm --network host --pid host --entrypoint portview <image> doctor
ENTRYPOINT ["portview", "mcp"]

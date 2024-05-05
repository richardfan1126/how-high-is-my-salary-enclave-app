ARG TARGET=x86_64-unknown-linux-gnu

## Build app binary using Rust base image
# rust:1.76.0-bookworm linux/amd64
FROM rust@sha256:64d3bd318978dcf63335c626fcc638ee8d8576735786ce9f9e8f22925acf256f as builder

ARG TARGET
ENV TARGET=${TARGET}

RUN rustup target add ${TARGET}

COPY app /app
WORKDIR /app

RUN cargo build --release --target=${TARGET}
RUN strip -s target/${TARGET}/release/how-high-is-my-salary

## Build socat using gcc base image
# gcc:12.3.0-bookworm linux/amd64
FROM gcc@sha256:b73155617da2815c4693e7e9992d12019ffeff890519be23d1055329c818005b as socat-builder

# Downloaded from http://www.dest-unreach.org/socat/download/socat-1.8.0.0.tar.gz
COPY lib/socat-1.8.0.0.tar.gz /src/socat-1.8.0.0.tar.gz

# Print sha256 checksum of source file
RUN sha256sum /src/socat-1.8.0.0.tar.gz

WORKDIR /src
RUN tar -xf socat-1.8.0.0.tar.gz

WORKDIR /src/socat-1.8.0.0
RUN ./configure --disable-openssl --disable-readline --disable-libwrap
RUN make
RUN make install

## Build net-tools
# gcc:12.3.0-bookworm linux/amd64
FROM gcc@sha256:b73155617da2815c4693e7e9992d12019ffeff890519be23d1055329c818005b as net-tools-builder

# Downloaded from https://sourceforge.net/projects/net-tools/
COPY lib/net-tools-2.10.tar.xz /src/net-tools-2.10.tar.xz

# Print sha256 checksum of source file
RUN sha256sum /src/net-tools-2.10.tar.xz

WORKDIR /src
RUN tar -xf net-tools-2.10.tar.xz

WORKDIR /src/net-tools-2.10
RUN yes "" | ./configure.sh config.in
RUN make
RUN make install

## Build the runtime image
# ubuntu:jammy-20240212 linux/amd64
FROM ubuntu@sha256:81bba8d1dde7fc1883b6e95cd46d6c9f4874374f2b360c8db82620b33f6b5ca1

ARG TARGET
ENV TARGET=${TARGET}

# COPY socat
COPY --from=socat-builder /usr/local/bin/socat /usr/bin
COPY --from=socat-builder /usr/local/bin/socat1 /usr/bin

# COPY ifconfig
COPY --from=net-tools-builder /usr/bin/ifconfig /usr/bin

WORKDIR /app

# Copy app binary
COPY --from=builder /app/target/${TARGET}/release/how-high-is-my-salary /app
RUN chmod +x /app/how-high-is-my-salary

# Copy entry script
COPY run.sh /app/run.sh

CMD ["/bin/sh", "-c", "/app/run.sh"]

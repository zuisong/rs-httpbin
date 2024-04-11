####################################################################################################
## Builder
####################################################################################################
FROM rust:latest AS builder

WORKDIR /httpbin

COPY ./ .

RUN cargo build --release

####################################################################################################
## Final image
####################################################################################################
FROM debian:stable-slim

WORKDIR /httpbin

# Copy our build
COPY --from=builder /httpbin/target/release/rs-httpbin ./

EXPOSE 3000

CMD ["/httpbin/rs-httpbin"]
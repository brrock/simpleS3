# Build stage
FROM rust:alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev

WORKDIR /app

# Copy Cargo files first for better caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm src/main.rs

# Copy source code and build the actual application
COPY src ./src
RUN touch src/main.rs && cargo build --release

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates wget

# Create app user
RUN addgroup -g 1000 s3user && \
    adduser -D -s /bin/sh -u 1000 -G s3user s3user
# Create data directory
RUN mkdir -p /data && chown s3user:s3user /data

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/target/release/simpleS3 /app/simpleS3

# Change ownership
RUN chown s3user:s3user /app/simpleS3

# Switch to non-root user
USER s3user

# Environment variables with defaults
ENV HOST=0.0.0.0
ENV PORT=9000
ENV BUCKET=simple-bucket
ENV ACCESS_KEY=mykey
ENV SECRET_KEY=mysecret
ENV DATA_DIR=/data


# Expose port
EXPOSE 9000

# Volume for data persistence
VOLUME ["/data"]

# Run the application
CMD ["./simpleS3"]
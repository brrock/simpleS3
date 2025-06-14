# simpleS3 - very simple s3 server - written in rust 
Easily hostable in docker compose and docker. Simple and fast. Currently only supports a single bucket.
## How to run
```sh
cargo build --release
mv target/release/simpleS3 .
chmod +x simpleS3 
./simpleS3
```
example docker compose 
```yaml
services:
  simple-s3:
    image: brrock/simple-s3
    ports:
      - "9000:9000"
    environment:
      - HOST=0.0.0.0
      - PORT=9000
      - BUCKET=my-bucket
      - ACCESS_KEY=minioadmin
      - SECRET_KEY=minioadmin123
      - DATA_DIR=/data
    volumes:
      - s3_data:/data
      # Or mount to host directory:
      # - ./s3-data:/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:9000/"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - s3-network

volumes:
  s3_data:

networks:
  s3-network:
    driver: bridge
```
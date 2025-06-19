# simpleS3 - very simple s3 server - written in rust 
Easily hostable in docker compose and docker. Simple and fast. Currently only supports a single bucket. The docker image is under 8mb (compressed, the whole image is 20mb) so it is incredibly small. It is perfect for people for people who need a quick s3 bucket and don't want to setup minIO, minIO is 54mb, use this and you get more space for files.
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
      - ACCESS_KEY=admin
      - SECRET_KEY=admin
      - DATA_DIR=/data
    volumes:
      - s3_data:/data
      # Or mount to host directory:
      # - ./s3-data:/data
    restart: unless-stopped
    networks:
      - s3-network

volumes:
  s3_data:

networks:
  s3-network:
    driver: bridge
```
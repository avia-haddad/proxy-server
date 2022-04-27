# Proxy Server
This is a multithreaded proxy server written in C. It uses a thread pool with a pre-defined number of maximum threads. When making a TCP request to the server, it adds the request to a queue of jobs, and lets a thread wake up to perform the job.

The server relays TCP requests, and can block pre-defined domains and IP addresses/subnets. It also caches the results for faster times on consecutive requests.

## Usage
Compile with:
```
gcc proxy_server.c thread_pool.c -o proxy_server
```

Run with
```
./proxy_server <port> <pool-size> <max-number-of-request> <filter>
```

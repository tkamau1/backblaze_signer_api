bind = "0.0.0.0:8080"
workers = 2
worker_class = "gthread"   # threads, not coroutines — fully compatible with gRPC
threads = 4                # 2 workers × 4 threads = 8 concurrent requests
timeout = 120
keepalive = 5

# backblaze_signer_api/gunicorn_config.py
bind = "0.0.0.0:8080"
workers = 2
worker_class = "gevent"
worker_connections = 100
timeout = 120
keepalive = 5

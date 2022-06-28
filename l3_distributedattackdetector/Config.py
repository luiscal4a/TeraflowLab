import logging

# General settings
LOG_LEVEL = logging.WARNING

# gRPC settings
GRPC_SERVICE_PORT = 10000  # TODO UPM FIXME
GRPC_MAX_WORKERS = 10
GRPC_GRACE_PERIOD = 60

# Prometheus settings
METRICS_PORT = 9192

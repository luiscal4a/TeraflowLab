import logging, signal, sys, threading, os
from prometheus_client import start_http_server
from Settings import get_setting
from l3_attackmitigatorService import l3_attackmitigatorService
from Config import GRPC_SERVICE_PORT, GRPC_MAX_WORKERS, GRPC_GRACE_PERIOD, LOG_LEVEL, METRICS_PORT

terminate = threading.Event()
logger = None

def signal_handler(signal, frame):
    global terminate, logger
    logger.warning('Terminate signal received')
    terminate.set()

def main():
    global terminate, logger
    
    service_port = get_setting('L3_ATTACKMITIGATOR_SERVICE_PORT_GRPC', default=GRPC_SERVICE_PORT)
    max_workers  = get_setting('MAX_WORKERS',                      default=GRPC_MAX_WORKERS )
    grace_period = get_setting('GRACE_PERIOD',                     default=GRPC_GRACE_PERIOD)
    log_level    = get_setting('LOG_LEVEL',                        default=LOG_LEVEL        )
    metrics_port = get_setting('METRICS_PORT',                     default=METRICS_PORT     )

    logging.basicConfig(level=log_level)
    logger = logging.getLogger(__name__)

    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info('Starting...')
    # Start metrics server
    start_http_server(metrics_port)

    # Starting l3_attackmitigator service
    grpc_service = l3_attackmitigatorService(
        port=service_port, max_workers=max_workers, grace_period=grace_period)
    grpc_service.start()

    # Wait for Ctrl+C or termination signal
    while not terminate.wait(timeout=0.1): pass

    logger.info('Terminating...')
    grpc_service.stop()

    logger.info('Bye')
    return 0

if __name__ == '__main__':
    sys.exit(main())

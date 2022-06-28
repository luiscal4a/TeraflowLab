from __future__ import print_function
import logging
from sys import stdout
from l3_attackmitigator_pb2 import (
    EmptyMitigator
)
from l3_attackmitigator_pb2_grpc import (
    L3AttackmitigatorServicer,
)

#  Setup loggers ===============================
logger = logging.getLogger('am_logger')
logger.setLevel(logging.INFO)
logFormatter = logging.Formatter(fmt='%(levelname)-8s %(message)s')
consoleHandler = logging.StreamHandler(stdout)
consoleHandler.setFormatter(logFormatter)
logger.addHandler(consoleHandler)
logger.propagate = False
# ==================================

class l3_attackmitigatorServiceServicerImpl(L3AttackmitigatorServicer):

    def __init__(self):
        logger.info("Creating Servicer...")
    
    def SendOutput(self, request_iterator, context):
        # SEND CONFIDENCE TO MITIGATION SERVER
        counter = 0
        for request in request_iterator:
            counter += 1
            if request.tag == 1:
                logger.info(f"CRYPTO({request.confidence}): {request.flow_id}")
        return EmptyMitigator(message=f"Mitigator received {counter} messages")

    def GetMitigation(self, request, context):
        # GET OR PERFORM MITIGATION STRATEGY
        logging.debug("")
        print("Returing mitigation strategy...")
        k = self.last_value * 2
        return EmptyMitigator(
            message=f"Mitigation with double confidence = {k}"
        )


    

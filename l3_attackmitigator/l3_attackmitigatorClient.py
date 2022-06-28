import grpc, logging
from common.tools.client.RetryDecorator import retry, delay_exponential
from l3_attackmitigator.proto.l3_attackmitigator_pb2_grpc import (
    L3AttackmitigatorStub,
)
from l3_attackmitigator.proto.l3_attackmitigator_pb2 import (
    Output,
    EmptyMitigator
)

LOGGER = logging.getLogger(__name__)
MAX_RETRIES = 15
DELAY_FUNCTION = delay_exponential(initial=0.01, increment=2.0, maximum=5.0)


class l3_attackmitigatorClient:
    def __init__(self, address, port):
        self.endpoint = "{}:{}".format(address, port)
        LOGGER.debug("Creating channel to {}...".format(self.endpoint))
        self.channel = None
        self.stub = None
        self.connect()
        LOGGER.debug("Channel created")

    def connect(self):
        self.channel = grpc.insecure_channel(self.endpoint)
        self.stub = L3AttackmitigatorStub(self.channel)

    def close(self):
        if self.channel is not None:
            self.channel.close()
        self.channel = None
        self.stub = None

    @retry(exceptions=set(), max_retries=MAX_RETRIES, delay_function=DELAY_FUNCTION, prepare_method_name='connect')
    def SendOutput(self, request: Output) -> EmptyMitigator:
        LOGGER.debug('SendOutput request: {}'.format(request))
        response = self.stub.SendOutput(request)
        LOGGER.debug('SendOutput result: {}'.format(response))
        return response

    @retry(exceptions=set(), max_retries=MAX_RETRIES, delay_function=DELAY_FUNCTION, prepare_method_name='connect')
    def GetMitigation(self, request: EmptyMitigator) -> EmptyMitigator:
        LOGGER.debug('GetMitigation request: {}'.format(request))
        response = self.stub.GetMitigation(request)
        LOGGER.debug('GetMitigation result: {}'.format(response))
        return response


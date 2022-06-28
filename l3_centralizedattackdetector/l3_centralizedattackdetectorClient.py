import grpc, logging
from common.tools.client.RetryDecorator import retry, delay_exponential
from l3_centralizedattackdetector.proto.l3_centralizedattackdetector_pb2_grpc import (
    L3CentralizedattackdetectorStub,
)
from l3_centralizedattackdetector.proto.l3_centralizedattackdetector_pb2 import (
    Empty,
    ModelInput,
    ModelOutput
)

LOGGER = logging.getLogger(__name__)
MAX_RETRIES = 15
DELAY_FUNCTION = delay_exponential(initial=0.01, increment=2.0, maximum=5.0)

class l3_centralizedattackdetectorClient:
    def __init__(self, address, port):
        self.endpoint = "{}:{}".format(address, port)
        LOGGER.debug("Creating channel to {}...".format(self.endpoint))
        self.channel = None
        self.stub = None
        self.connect()
        LOGGER.debug("Channel created")

    def connect(self):
        self.channel = grpc.insecure_channel(self.endpoint)
        self.stub = L3CentralizedattackdetectorStub(self.channel)

    def close(self):
        if self.channel is not None:
            self.channel.close()
        self.channel = None
        self.stub = None

    @retry(exceptions=set(), max_retries=MAX_RETRIES, delay_function=DELAY_FUNCTION, prepare_method_name='connect')
    def SendInput(self, request: ModelInput) -> Empty:
        LOGGER.debug('SendInput request: {}'.format(request))
        response = self.stub.SendInput(request)
        LOGGER.debug('SendInput result: {}'.format(response))
        return response
    
    @retry(exceptions=set(), max_retries=MAX_RETRIES, delay_function=DELAY_FUNCTION, prepare_method_name='connect')
    def GetOutput(self, request: Empty) -> ModelOutput:
        LOGGER.debug('GetOutput request: {}'.format(request))
        response = self.stub.GetOutput(request)
        LOGGER.debug('GetOutput result: {}'.format(response))
        return response



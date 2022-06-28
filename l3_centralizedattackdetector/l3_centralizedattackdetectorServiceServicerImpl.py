from __future__ import print_function
from datetime import datetime
from sys import stdout
import os
import grpc
import time
import numpy as np
import onnxruntime as rt
import logging
from sklearn.metrics import confusion_matrix
from l3_centralizedattackdetector_pb2 import (
    Empty,
)
from l3_centralizedattackdetector_pb2_grpc import (
    L3CentralizedattackdetectorServicer,
)

from l3_attackmitigator_pb2 import (
    Output,
)
from l3_attackmitigator_pb2_grpc import (
    L3AttackmitigatorStub,
)

#  Setup loggers ===============================
logger = logging.getLogger('cad_logger')
logger.setLevel(logging.INFO)
logFormatter = logging.Formatter(fmt='%(levelname)-8s %(message)s')
consoleHandler = logging.StreamHandler(stdout)
consoleHandler.setFormatter(logFormatter)
logger.addHandler(consoleHandler)
logger.propagate = False
# ==================================

here = os.path.dirname(os.path.abspath(__file__))
MODEL_FILE = os.path.join(here, "ml_model/teraflow_rf_local.onnx")
ATTACK_MITIGATOR = "am:10002"

class l3_centralizedattackdetectorServiceServicerImpl(L3CentralizedattackdetectorServicer):

    def __init__(self):
        logger.info("Creating Servicer...")
        self.model = rt.InferenceSession(MODEL_FILE)
        self.input_name = self.model.get_inputs()[0].name
        self.label_name = self.model.get_outputs()[0].name
        self.prob_name = self.model.get_outputs()[1].name
        
        self.counter = 0
        self.tags = []
        self.predicted = []

    def tagger(self, c_ip, s_ip):
        c_pool = ['10.0.27.14','10.0.20.19']
        s_pool = ['94.130.12.30']
        return 1 if (c_ip in c_pool) and (s_ip in s_pool) else 0
    
    def make_inference(self, requests):
        # ML MODEL
        x_data = np.array([
                [
                    request.n_packets_server_seconds,
                    request.n_packets_client_seconds,
                    request.n_bits_server_seconds,
                    request.n_bits_client_seconds,
                    request.n_bits_server_n_packets_server,
                    request.n_bits_client_n_packets_client,
                    request.n_packets_server_n_packets_client,
                    request.n_bits_server_n_bits_client,
                ] for request in requests
            ])

        predictions = self.model.run([self.prob_name], {self.input_name: x_data.astype(np.float32)})[0]
        
        # Output format
        output = []
        for request, prediction in zip(requests, predictions):
            output_message = {
                "confidence": None,
                "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                "ip_o": request.ip_o,
                "tag_name": None,
                "tag": None,
                "flow_id": request.flow_id,
                "protocol": request.protocol,
                "port_d": request.port_d,
                "ml_id": "RandomForest",
                "time_start": request.time_start,
                "time_end": request.time_end,
            }
            if prediction[1] >= 0.6:
                output_message["confidence"] = prediction[1]
                output_message["tag_name"] = "Crypto"
                output_message["tag"] = 1
                self.predicted.append(1)
            else:
                output_message["confidence"] = prediction[0]
                output_message["tag_name"] = "Normal"
                output_message["tag"] = 0
                self.predicted.append(0)
            
            self.tags.append(self.tagger(request.ip_o, request.ip_d))
            output.append(Output(**output_message))
        return output
    
    def SendInput(self, request_iterator, context):
        # PERFORM INFERENCE WITH SENT INPUTS
        def process_data():
            self.counter = 0
            process_time = 0
            last_time = time.time()
            requests = []
            for request in request_iterator:
                self.counter += 1
                requests.append(request)
                if time.time() - last_time >= 1:
                    start_process = time.time()
                    output = self.make_inference(requests)  # MAKE INFERENCE
                    process_time += time.time() - start_process

                    logger.info("Time: {0} | Packets {1} | Average: {2}".format(process_time, self.counter, process_time/self.counter))
                    logger.info("Cryptos: {0} out of {1}".format(sum(self.predicted), sum(self.tags)))
                    last_time = time.time()
                    #logger.info("{0}".format(confusion_matrix(self.tags, self.predicted)))
                    for msg in output:
                        yield msg
                    requests = []
       
        with grpc.insecure_channel(ATTACK_MITIGATOR) as channel:
            stub = L3AttackmitigatorStub(channel)
            print(stub.SendOutput(process_data()))
            return Empty(message=f"Received {self.counter} messages")
    
    def GetOutput(self, request, context):
        print("Returing inference output...")
        return None



    

import logging
from sys import stdout
import sys 
import os 
import time
import signal
import grpc
import subprocess
from l3_centralizedattackdetector_pb2_grpc import (
    L3CentralizedattackdetectorStub,
)
from l3_centralizedattackdetector_pb2 import (
    ModelInput,
)

#  Setup loggers ===============================
logger = logging.getLogger('dad_logger')
logger.setLevel(logging.INFO)
logFormatter = logging.Formatter(fmt='%(levelname)-8s %(message)s')
consoleHandler = logging.StreamHandler(stdout)
consoleHandler.setFormatter(logFormatter)
logger.addHandler(consoleHandler)
# ==================================

TSTAT_DIR_NAME = "piped/"
CENTRALIZED_ATTACK_DETECTOR = "localhost:10001"
JSON_BLANK = {
    "ip_o": "",  # Client IP
    "port_o": "",  # Client port
    "ip_d": "",  # Server ip
    "port_d": "",  # Server port
    "flow_id": "",  # Identifier:c_ip,c_port,s_ip,s_port,time_start
    "protocol": "",  # Connection protocol
    "time_start": 0,  # Start of connection
    "time_end": 0,  # Time of last packet
}
MSG = 0
STOP = False

def handler(signum, frame):
    global STOP
    if STOP:
        exit()
    STOP = True
    logger.info("Gracefully Stopping...")
signal.signal(signal.SIGINT, handler)

def follow(thefile, time_sleep):
    """
    Generator function that yields new lines in a file
    It reads the logfie (the opened file)
    """
    # seek the end of the file
    thefile.seek(0, os.SEEK_END)

    trozo = ""
    # start infinite loop
    while True:
        # read last line of file
        line = thefile.readline()
        # sleep if file hasn't been updated
        if not line:
            time.sleep(time_sleep)
            continue
        if line[-1] != "\n":
            trozo += line
        else:
            if trozo != "":
                line = trozo + line
                trozo = ""
            yield line

def load_file(dirname=TSTAT_DIR_NAME): # - Client side -
    while True:
        here = os.path.dirname(os.path.abspath(__file__))
        tstat_piped = os.path.join(here, dirname)
        tstat_dirs = os.listdir(tstat_piped)
        if len(tstat_dirs) > 0:
            tstat_dirs.sort()
            new_dir = tstat_dirs[-1]
            tstat_file = tstat_piped + new_dir + "/log_tcp_temp_complete"
            logger.info("Following: {0}".format(tstat_file))
            return tstat_file
        else:
            logger.info("No tstat directory!")
            time.sleep(5)

def process_line(line):
    """
    - Preprocessing before a message per line
    - Avoids crash when nan are found by generating a 0s array
    - Returns a list of values
    """
    def makeDivision(i, j): #Helper function
        return i / j if (j and type(i) != str and type(j) != str) else 0

    line = line.split(" ")
    try:
        n_packets_server, n_packets_client = float(line[16]), float(line[2])
    except:
        return [0 for i in range(9)]
    
    n_bits_server, n_bits_client = float(line[22])*8, float(line[8])*8
    seconds = float(line[30])  # Duration in s
    values = [
        makeDivision(n_packets_server, seconds),
        makeDivision(n_packets_client, seconds),
        makeDivision(n_bits_server, seconds),
        makeDivision(n_bits_client, seconds),
        makeDivision(n_bits_server, n_packets_server),
        makeDivision(n_bits_client, n_packets_client),
        makeDivision(n_packets_server, n_packets_client),
        makeDivision(n_bits_server, n_bits_client),
    ]
    
    return values

def open_channel():
    with grpc.insecure_channel(CENTRALIZED_ATTACK_DETECTOR) as channel:
        stub = L3CentralizedattackdetectorStub(channel)
        logger.info("{0}".format(stub.SendInput(run())))

def run():
    filename = load_file()
    logfile = open(filename, "r")
    loglines = follow(logfile, 5)
    
    new_connections = {}  # Dict for storing NEW data
    connections_db = {}  # Dict for storing ALL data
    
    process_time = []
    global MSG
    global STOP
    for line in loglines:
        if STOP:
            break
        MSG += 1
        start = time.time()
        line_id = line.split(" ")
        conn_id = (line_id[0], line_id[1], line_id[14], line_id[15])
        new_connections[conn_id] = process_line(line)
        try:
            connections_db[conn_id]["time_end"] = time.time()
        except KeyError:
            connections_db[conn_id] = JSON_BLANK.copy()
            connections_db[conn_id]["time_start"] = time.time()
            connections_db[conn_id]["time_end"] = time.time()
            connections_db[conn_id]["ip_o"] = conn_id[0]
            connections_db[conn_id]["port_o"] = conn_id[1]
            connections_db[conn_id]["flow_id"] = ":".join(conn_id)
            connections_db[conn_id]["protocol"] = "TCP"
            connections_db[conn_id]["ip_d"] = conn_id[2]
            connections_db[conn_id]["port_d"] = conn_id[3]

        # CRAFT DICT
        inference_information = {
            "n_packets_server_seconds": new_connections[conn_id][0],
            "n_packets_client_seconds": new_connections[conn_id][1],
            "n_bits_server_seconds": new_connections[conn_id][2],
            "n_bits_client_seconds": new_connections[conn_id][3],
            "n_bits_server_n_packets_server": new_connections[conn_id][4],
            "n_bits_client_n_packets_client": new_connections[conn_id][5],
            "n_packets_server_n_packets_client": new_connections[conn_id][6],
            "n_bits_server_n_bits_client": new_connections[conn_id][7],
            "ip_o": connections_db[conn_id]["ip_o"],
            "port_o": connections_db[conn_id]["port_o"],
            "ip_d": connections_db[conn_id]["ip_d"],
            "port_d": connections_db[conn_id]["port_d"],
            "flow_id": connections_db[conn_id]["flow_id"],
            "protocol": connections_db[conn_id]["protocol"],
            "time_start": connections_db[conn_id]["time_start"],
            "time_end": connections_db[conn_id]["time_end"],
        }

        process_time.append(time.time() - start)
        if MSG % 1000 == 0:
            logger.info("Lineas: {0}- Tiempo Medio Procesado: {1}".format(MSG, sum(process_time)/MSG))
        
        yield ModelInput(**inference_information)
    

def main():
    open_channel()
    
if __name__ == '__main__':
    sys.exit(main())

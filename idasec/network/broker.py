#!/usr/bin/env python
import json
import random
import struct
from threading import Thread

import zmq

from idasec.dba_printer import *
from idasec.network.commands import *
from idasec.network.message import *
from idasec.proto import config_pb2
from idasec.protobuf_json import json2pb


class Broker:
    def __init__(self, binsec_recv_cb=None, pinsec_recv_cb=None):
        self.context = zmq.Context.instance()
        self.pinsec_socket = self.context.socket(zmq.DEALER)
        self.binsec_socket = self.context.socket(zmq.DEALER)
        self.binsec_callback = binsec_recv_cb if binsec_recv_cb is not None else self.dispatch_from_binsec
        self.pinsec_callback = pinsec_recv_cb if pinsec_recv_cb is not None else self.disconnect_pinsec
        self.binsec_socket.identity = str(random.randint(0, sys.maxint))
        self.th = None
        self.stop = False
        self.binsec_addr = ""
        self.pinsec_addr = ""

    def connect_pinsec(self, ip, port):
        self.pinsec_addr = "tcp://"+ip+":"+str(port)
        self.pinsec_socket.connect(self.pinsec_addr)

    def connect_binsec(self, ip, port):
        self.binsec_addr = "tcp://"+ip+":"+str(port)
        self.binsec_socket.connect(self.binsec_addr)

    def disconnect_binsec(self):
        self.binsec_socket.disconnect(self.binsec_addr)

    def disconnect_pinsec(self):
        self.pinsec_socket.disconnect(self.pinsec_addr)

    def bind_pin(self, port):
        self.pinsec_socket.bind("tcp://*:"+port)

    def bind_binsec(self, port):
        self.binsec_socket.bind("tcp://*:"+port)

    def run_broker_loop_thread(self):
        self.th = Thread(target=self.run_broker_loop)
        self.th.start()

    def run_broker_loop(self):
        for origin, cmd, data in self.run_broker_loop_generator():
            if origin == "PINSEC":
                self.pinsec_callback(cmd, data)
            elif origin == "BINSEC":
                self.binsec_callback(cmd, data)
            else:
                pass

    def run_broker_loop_generator(self):
        poll = zmq.Poller()
        poll.register(self.binsec_socket, zmq.POLLIN)
        poll.register(self.pinsec_socket, zmq.POLLIN)
        # print "start iterating"
        try:
            while True:
                sockets = dict(poll.poll(timeout=100))
                if sockets == {}:
                    yield None, None, None
                if self.stop:
                    print "Thread loop stop"
                    break

                if self.pinsec_socket in sockets:
                    cmd, data = self.pinsec_socket.recv_multipart()
                    yield PINSEC, cmd, data
                    # self.pinsec_callback(cmd, data)

                if self.binsec_socket in sockets:
                    cmd, data = self.binsec_socket.recv_multipart()
                    yield BINSEC, cmd, data
                    # self.binsec_callback(cmd, msg)

        except KeyboardInterrupt:
            self.binsec_socket.close()
            self.pinsec_socket.close()

    def dispatch_from_pin(self, cmd, data):
        self.binsec_socket.send_multipart([cmd, data])

    def dispatch_from_binsec(self, cmd, data):
        self.pinsec_socket.send_multipart([cmd, data])

    def send_binsec_message(self, cmd, data, blocking=True):
        self.send_message(self.binsec_socket, cmd, data, blocking=blocking)

    def send_pinsec_message(self, cmd, data, blocking=True):
        self.send_message(self.pinsec_socket, cmd, data, blocking=blocking)

    @staticmethod
    def send_message(socket, cmd, data, blocking=True):
        flags = 0 if blocking else zmq.DONTWAIT
        socket.send_multipart([cmd, data], flags=flags)

    def receive_binsec_message(self, blocking=True):
        return self.receive_message(self.binsec_socket, blocking=blocking)

    def receive_pinsec_message(self, blocking=True):
        return self.receive_message(self.pinsec_socket, blocking=blocking)

    @staticmethod
    def receive_message(socket, blocking=True):
        flags = 0 if blocking else zmq.NOBLOCK
        try:
            cmd, data = socket.recv_multipart(flags=flags)
            return cmd, data
        except zmq.Again:
            return None, None
        except zmq.ContextTerminated:
            print("Context terminated ..")
            return None, None
        except KeyboardInterrupt:
            return None, None

    def terminate(self):
        if self.th is not None:
            self.stop = True
        self.binsec_socket.close()
        self.pinsec_socket.close()


def decode_instr(opcode):
    mess = MessageDecodeInstr(kind="hexa", instrs=opcode, base_addrs=0)
    raw = mess.serialize()
    broker = Broker()
    broker.connect_binsec("localhost", "5570")
    broker.send_binsec_message("DECODE_INSTR", raw)
    cmd, data = broker.receive_binsec_message()
    print "CMD:", cmd, "data:", len(data)
    reply = MessageDecodeInstrReply()
    reply.parse(data)
    for opc, dbainsts in reply.instrs:
        print(opc)
        for i in dbainsts:
            print instr_to_string(i)
    broker.terminate()


def load_config(name):
    f = open(name, "r")
    js = json.loads(f.read())
    f.close()
    return json2pb(config_pb2.configuration(), js)


class AnalysisBroker(Broker):
    def __init__(self):
        Broker.__init__(self)

    def dispatch_from_binsec(self, cmd, data):
        if cmd in ["PATCH_ZF", "RESUME"]:
            self.send_pinsec_message(cmd, data)
        else:
            print cmd, data


def launch_full_proxy_analysis(conf_name):
    conf = load_config(conf_name)
    broker = AnalysisBroker()
    broker.connect_binsec("127.0.0.1", '5570')
    data = conf.SerializeToString()
    broker.send_binsec_message("START_ANALYSIS", data)
    broker.connect_pinsec("192.168.56.101", "5555")
    broker.run_broker_loop()


def launch_analysis(trace_name, conf_name):
    conf = load_config(conf_name)
    broker = Broker()
    broker.connect_binsec("127.0.0.1", '5570')
    data = conf.SerializeToString()
    f = open("config_serialized.pb", "w")
    f.write(data)
    f.close()
    broker.send_binsec_message("START_ANALYSIS", data)
    f = open(trace_name, "rb")
    read_finished = False
    first_chunk = True
    i = 1
    while 1:
        cmd, data = broker.receive_binsec_message(read_finished)
        if cmd is not None and data is not None:
            print i, ":", cmd, repr(data)
            i += 1
            if cmd == "END":
                break
        if not read_finished:
            data = f.read(4)
            if data == "":
                read_finished = True
                broker.send_binsec_message("END", "STUB")
                f.close()
            else:
                size, = struct.unpack("I", data)
                data = f.read(size)
                if first_chunk:
                    broker.send_binsec_message("TRACE_HEADER", data)
                    first_chunk = False
                else:
                    broker.send_binsec_message("TRACE_CHUNK", data)
    broker.terminate()


def main():
    if len(sys.argv) <= 1:
        print("Usage: ./broker.py COMMAND args")
        exit(1)
    command = sys.argv[1]
    if command == "broker":
        broker = Broker()
        broker.bind_binsec("5555")
        broker.connect_pinsec(sys.argv[2], sys.argv[3])
        broker.run_broker_loop()
    elif command == "DECODE_INSTR":
        decode_instr(sys.argv[2])
    elif command == "START_ANALYSIS":
        launch_analysis(sys.argv[2], sys.argv[3])
    elif command == "FULL_PROXY":
        launch_full_proxy_analysis(sys.argv[2])
    else:
        pass


if __name__ == "__main__":
    main()

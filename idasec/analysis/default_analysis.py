import datetime

from idasec.broker import Broker
from PyQt5 import QtGui, QtCore, QtWidgets
from idasec.trace import raw_parse_trace
from idasec.commands import *

STATIC = 0
DYNAMIC = 1
STATIC_AND_DYNAMIC = 2


class DefaultAnalysis:
    config_widget = None
    kind = DYNAMIC
    name = "Default"

    @staticmethod
    def on_analysis_selected(widget):
        pass

    def __init__(self, parent, config, is_stream=False, trace=None):
        self.parent = parent
        self.configuration = config
        self.broker = Broker()
        self.result_widget = QtWidgets.QTextEdit()
        self.is_stream = is_stream
        self.trace_input_generator = None
        self.analyse_finished = False
        self.trace_finished = False
        if not is_stream and trace is not None:
            self.trace_input_generator = raw_parse_trace(trace.filename)

    def run(self):
        self.log("LOG", "Start analysis:"+self.name)
        raw_conf = self.configuration.SerializeToString()
        self.broker.send_binsec_message(START_ANALYSIS, raw_conf)

        for origin, cmd, data in self.broker.run_broker_loop_generator():
            QtWidgets.QApplication.processEvents()

            if not self.is_stream:
                self.send_trace_chunk_if_any()

            if origin == BINSEC:
                if cmd == "END":
                    self.analyse_finished = True
                    self.analysis_terminated()
                    break
                else:
                    self.binsec_message_received(cmd, data)
            elif origin == PINSEC:
                self.pinsec_message_received(cmd, data)

    def send_trace_chunk_if_any(self):
        if not self.trace_finished:
            try:
                trace_cmd, trace_data = self.trace_input_generator.next()
                self.broker.send_binsec_message(trace_cmd, trace_data)
            except StopIteration:
                self.trace_finished = True
                self.log("LOG", "All the trace sent")
                self.broker.send_binsec_message(END, EMPTY)

    def pinsec_message_received(self, cmd, data):
        self.log("LOG", "Message received:%s" % cmd, origin="PINSEC")
        self.broker.send_binsec_message(cmd, data)

    def binsec_message_received(self, cmd, data):
        self.result_widget.append("Binsec message received:%s -> %s" % (cmd, data))
        if cmd in ["PATCH_ZF", "RESUME"]:
            self.broker.send_pinsec_message(cmd, data)

    def analysis_terminated(self):
        self.log("LOG", "Analysis %s terminated" % self.name)
        self.broker.terminate()

    def stop(self):
        self.log("LOG", "Close analysis %s" % self.name)
        if not self.analyse_finished:
            self.broker.send_binsec_message(EXIT, EMPTY)
        self.broker.terminate()

    def log(self, typ, message, origin="IDASec"):
        self.parent.log(typ, message, origin=origin)

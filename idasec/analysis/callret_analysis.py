# -*- coding: utf-8 -*-

import idc

from idasec.commands import *
from idasec.analysis.default_analysis import DefaultAnalysis
from idasec.proto.analysis_config_pb2 import callret_analysis_results
from idasec.report_generator import make_cell, RED, GREEN, HTMLReport
from idasec.widgets.StandardParamWidget import StandardParamConfigWidget
from idasec.widgets.StandardResultWidget import StandardResultWidget


# ============================ RESULT CLASS (pb dependant) =============================
def to_status_name(x):
    return {callret_analysis_results.OK: "OK", callret_analysis_results.VIOL:"VIOLATION"}[x]


def to_label_name(x):
    return callret_analysis_results.callret_labels.DESCRIPTOR.values_by_number[x].name


class RetInfo:
    def __init__(self, addr, status, labels, returnsites, count):
        self.addr = addr
        self.status = status
        self.labels = labels
        self.returnsites = returnsites
        self.solve_count = count
        self.calls = []

    def get_status(self):
        return to_status_name(self.status)

    def is_tampering(self):
        return self.status == callret_analysis_results.VIOL

    def is_aligned(self):
        return len([x == callret_analysis_results.ALIGNED for x in self.labels]) != 0

    def is_disaligned(self):
        return len([x == callret_analysis_results.DISALIGNED for x in self.labels]) != 0

    def is_single(self):
        return len([x == callret_analysis_results.SINGLE for x in self.labels]) != 0

    def get_labels(self):
        return [to_label_name(x) for x in self.labels]

    def add_call(self, addr, st):
        self.calls.append((addr, st))

    def to_string(self):
        st = to_status_name(self.status)
        str_label = [to_label_name(x) for x in self.labels]
        calls_s = str([("%x" % x[0], to_status_name(x[1])) for x in self.calls])
        return "%x(%d): %s labels:%s returnsites:%s calls:%s" % \
               (self.addr, self.solve_count, st, str(str_label), str(["%x" % x for x in self.returnsites]), calls_s)


class CallRetResults:
    def __init__(self):
        self.rets = []

    def parse(self, data):
        pb = callret_analysis_results()
        pb.ParseFromString(data)

        for data in pb.values:
            ret = RetInfo(data.ret_addr, data.status, data.labels, data.returnsites, data.solve_count)
            for call in data.calls:
                ret.add_call(call.addr, call.status)
            self.rets.append(ret)

    def get_ok_viol(self):
        ok = 0
        viol = 0
        for ret in self.rets:
            if ret.is_tampering():
                viol += 1
            else:
                ok += 1
        return ok, viol

    def __iter__(self):
        return iter(self.rets)


# ===================================== ANALYSIS =======================================
# ======================================================================================

class CallRetAnalysis(DefaultAnalysis):

    config_widget = StandardParamConfigWidget()
    name = "callret"

    ANNOT_CODE = "Annotate code"
    GENERATE_PLOT = "Generate plot chart"

    def __init__(self, parent, config, is_stream=False, trace=None):
        DefaultAnalysis.__init__(self, parent, config, is_stream, trace)
        self.actions = {self.ANNOT_CODE: (self.annotate_code, False),
                        self.GENERATE_PLOT: (self.generate_chart, False)}
        self.results = CallRetResults()
        self.result_widget = StandardResultWidget(self)

    def binsec_message_received(self, cmd, data):
        if cmd == ANALYSIS_RESULTS:
            print "Analysis results received !"
            self.results.parse(data)
        else:
            self.log(cmd, data, origin="BINSEC")

    def analysis_terminated(self):
        self.result_widget.action_selector.setEnabled(True)
        self.result_widget.action_button.setEnabled(True)
        report = HTMLReport()
        report.add_title("Call stack results", size=2)
        report.add_table_header(['address', "status", "hit count", "labels", "return addresses", "calls"])
        for ret in self.results:
            addr = make_cell("%x" % ret.addr)
            status = make_cell(ret.get_status(), bold=ret.is_tampering(), color=RED if ret.is_tampering() else GREEN)
            labels_s = make_cell(''.join(["[%s]" % x for x in ret.get_labels()]))
            return_s = make_cell(''.join(["%x," % x for x in ret.returnsites])[:-1])
            call_s = make_cell(''.join(["%x:%s<br/>" % (x[0], to_status_name(x[1])) for x in ret.calls])[:-5])
            report.add_table_line([addr, status, make_cell(str(ret.solve_count)), labels_s, return_s, call_s])
        report.end_table()
        data = report.generate()
        self.result_widget.webview.setHtml(data)

    def annotate_code(self, enabled):
        for ret_data in self.results:
            addr = ret_data.addr
            if not enabled:  # Set the comment
                status_s = ret_data.get_status()
                labels_s = ''.join(["[%s]" % x for x in ret_data.get_labels()])
                comment = "Status:%s %s" % (status_s, labels_s)
                if ret_data.is_tampering():
                    comment += ' Ret:%s' % str(["%x" % x for x in ret_data.returnsites])
                idc.MakeRptCmt(addr, comment)
            else:  # Remove the comment
                idc.MakeRptCmt(addr, "")

        self.actions[self.ANNOT_CODE] = (self.annotate_code, not enabled)
        self.result_widget.action_selector_changed(self.ANNOT_CODE)

    def generate_chart(self, _):
        try:
            import plotly
            import plotly.graph_objs as go
            data = [[0, 0, 0], [0, 0, 0]]
            ok, viol = self.results.get_ok_viol()
            x = ["OK (%d)" % ok, "Tampering (%d)" % viol]
            for ret in self.results:
                i = 1 if ret.is_tampering() else 0
                data[i][0] += ret.is_aligned()
                data[i][1] += ret.is_disaligned()
                data[i][2] += ret.is_single()
            final_data = [go.Bar(x=x, y=[x[0] for x in data], name="Aligned"), go.Bar(x=x, y=[x[1] for x in data], name="Disaligned"), go.Bar(x=x, y=[x[2] for x in data], name="Single")]
            fig = go.Figure(data=final_data, layout=go.Layout(barmode='group', title='Call stack tampering labels'))
            plotly.offline.plot(fig, output_type='file', include_plotlyjs=True, auto_open=True)
        except ImportError:
            self.log("ERROR", "Plotly module not available")

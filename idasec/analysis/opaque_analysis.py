# -*- coding: utf-8 -*-

from PySide import QtGui, QtCore
from PySide.QtGui import QWidget
from idasec.commands import *
from idasec.analysis.default_analysis import DefaultAnalysis
from idasec.proto.analysis_config_pb2 import po_analysis_results
from idasec.report_generator import make_cell, RED, GREEN, PURPLE, HTMLReport
from idasec.widgets.StandardParamWidget import StandardParamConfigWidget
from idasec.widgets.StandardResultWidget import StandardResultWidget
from collections import namedtuple

import idc
import idautils
import idasec.ui.resources_rc


# ============================= RESULT CLASS (pb dependant) ==========================
def to_status_name(x):
    return {po_analysis_results.UNKNOWN : "Unknown",
            po_analysis_results.NOT_OPAQUE: "Covered",
            po_analysis_results.OPAQUE: "Opaque",
            po_analysis_results.LIKELY: "Unknown"}[x]


def to_alive_branch(status, branch):
    return {po_analysis_results.UNKNOWN : "/",
            po_analysis_results.NOT_OPAQUE: "*",
            po_analysis_results.OPAQUE: "%x" % branch,
            po_analysis_results.LIKELY: "/"}[status]


def status_to_color(x):
    return {po_analysis_results.UNKNOWN:PURPLE,
            po_analysis_results.LIKELY: PURPLE,
            po_analysis_results.NOT_OPAQUE:GREEN,
            po_analysis_results.OPAQUE:RED}[x]

AddrRet = namedtuple("AddrRet", "status nb_paths alive_branch")

class POResults(dict):
    def __init__(self):
        super(POResults, self).__init__()
        self.k = 0

    def parse(self, data):
        pb = po_analysis_results()
        pb.ParseFromString(data)

        for data in pb.values:
            addr = data.jmp_addr
            self.k = data.ksteps
            self.__setitem__(addr, AddrRet(data.status, data.nb_paths, data.alive_branch))

# ===================================== ANALYSIS =======================================
# ======================================================================================


class OpaqueAnalysis(DefaultAnalysis):

    config_widget = StandardParamConfigWidget()
    name = "opaque"

    ANNOT_CODE = "Annotate code"
    GENERATE_PLOT = "Generate plot chart"
    HIGHLIGHT_DEAD_BRANCHES = "Highlight dead branches"

    @staticmethod
    def on_analysis_selected(widget):
        widget.direction_selector_changed("Backward")

    def __init__(self, parent, config, is_stream=False, trace=None):
        DefaultAnalysis.__init__(self, parent, config, is_stream, trace)
        self.actions = {self.ANNOT_CODE: (self.annotate_code, False),
#                        self.GENERATE_PLOT: (self.generate_chart, False),
                        self.HIGHLIGHT_DEAD_BRANCHES: (self.highlight_dead, False)}
        self.results = POResults()
        self.marked_addresses = {}
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
        report.add_title("Opaque predicates results k="+(str(self.results.k)), size=3)
        report.add_table_header(['address',"status","nb path(tested)","alive branch"])
        for addr in sorted(self.results.keys()):
            infos = self.results[addr]
            addr = make_cell("%x" % addr)
            status, color = to_status_name(infos.status), status_to_color(infos.status)
            status = make_cell(status, bold=True, color=color)
            alive_br = to_alive_branch(infos.status, infos.alive_branch)
            report.add_table_line([addr, status, make_cell(str(infos.nb_paths)), make_cell(alive_br)])
            #TODO: Compute the number of possible paths for each predicate
        report.end_table()
        data = report.generate()
        self.result_widget.webview.setHtml(data)

    def annotate_code(self, enabled):
        for addr, infos in self.results.items():
            if not enabled:
                status = to_status_name(infos.status)
                idc.MakeRptCmt(addr, status)
            else:
                idc.MakeRptCmt(addr, "")
        self.actions[self.ANNOT_CODE] = (self.annotate_code, not(enabled))
        self.result_widget.action_selector_changed(self.ANNOT_CODE)

#    def generate_chart(self, enabled):
#        print "not implemented yet"
#        pass#TODO: To implement

    @staticmethod
    def make_po_pair(ea, alive):
        dead = [x for x in idautils.CodeRefsFrom(ea,True) if x != alive]
        return alive, dead[0]

    def highlight_dead(self, enabled):
        opaque_map = {k:self.make_po_pair(k,v.alive_branch) for k,v in self.results.items() if v.status == po_analysis_results.OPAQUE}
        for addr, (good, dead) in opaque_map.items():
            if not enabled: #Mark instructions
                print "propagate dead branch:%x" % addr
                self.propagate_dead_code(dead, opaque_map)
            else:
                for addr in self.marked_addresses.keys():
                    idc.SetColor(addr, idc.CIC_ITEM, 0xffffff)
                self.marked_addresses.clear()
        self.actions[self.HIGHLIGHT_DEAD_BRANCHES] = (self.highlight_dead, not(enabled))
        self.result_widget.action_selector_changed(self.HIGHLIGHT_DEAD_BRANCHES)

    def dead_br_of_op(self,ea, pred, op_map):
        if op_map.has_key(pred):
            good, bad = op_map[pred]
            return ea == bad
        else:
            return False

    def propagate_dead_code(self,ea,op_map):
        prevs = [x for x in idautils.CodeRefsTo(ea,True) if not self.marked_addresses.has_key(x) and not self.dead_br_of_op(ea, x, op_map)]
        if prevs == []: #IF there is no legit predecessors
            idc.SetColor(ea, idc.CIC_ITEM, 0x0000ff)
            self.marked_addresses[ea] = None
            succs = [x for x in idautils.CodeRefsFrom(ea,True)]
            for succ in succs:
                self.propagate_dead_code(succ, op_map)
        else:
            return

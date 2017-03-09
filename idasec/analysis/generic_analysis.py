# -*- coding: utf-8 -*-

import cgi
import subprocess
from PyQt5 import QtWidgets

import idasec.utils as utils
import idc
from idasec.analysis.default_analysis import DefaultAnalysis
from idasec.formula import SMTFormula
from idasec.network.commands import *
from idasec.proto.analysis_config_pb2 import generic_analysis, generic_analysis_results, specific_parameters_t
from idasec.proto.common_pb2 import *
from idasec.report_generator import *
from idasec.ui.generic_analysis_result_ui import Ui_generic_analysis_result
from idasec.ui.generic_analysis_ui import Ui_generic_analysis_widget


# ======================== RESULT CLASS (pb dependant) ========================
def smtpb_to_result(val):
    return {SAT: ("SAT", GREEN), UNKNOWN: ("UNKNOWN", PURPLE), UNSAT: ("UNSAT", RED), TIMEOUT: ("TIMEOUT", BLUE)}[val]


class GenericResults:
    def __init__(self, params):
        # -- params
        self.query = params.dba
        self.from_addr, self.to_addr = params.from_addr, params.to_addr
        self.get_formula = params.get_formula
        self.target = params.target_addr

        # -- results
        self.values = []
        self.status = None
        self.color = None
        self.formula = '"'

    def parse(self, data):
        res = generic_analysis_results()
        res.ParseFromString(data)
        for v in res.values:
            self.values.append(v)
        self.formula = res.smt_formula
        self.status, self.color = smtpb_to_result(res.result)

    def has_formula(self):
        return self.get_formula and self.formula != ""

    def has_values(self):
        return self.values != []

    def get_status(self):
        return self.status


# ================================  CONFIG CLASS =====================================
# ====================================================================================
class GenericAnalysisConfigWidget(QtWidgets.QWidget, Ui_generic_analysis_widget):

    def __init__(self):
        super(GenericAnalysisConfigWidget, self).__init__()
        self.conf = generic_analysis()
        self.setupUi(self)
        self.set_visbility_stuff(False)
        self.satisfiability_radiobutton.setChecked(True)
        self.from_button.clicked.connect(self.from_button_clicked)
        self.to_button.clicked.connect(self.to_button_clicked)
        self.restrict_from_button.clicked.connect(self.restrict_from_button_clicked)
        self.restrict_to_button.clicked.connect(self.restrict_to_button_clicked)
        self.target_addr_button.clicked.connect(self.target_addr_button_clicked)
        self.dba_help_button.clicked.connect(self.dba_help_button_clicked)
        self.values_radiobutton.toggled.connect(self.values_radiobutton_toggled)

    def set_fields(self, json_fields):
        gen = json_fields["generic_params"]
        if "target_addr" in gen:
            self.target_addr_field.setText(hex(gen["target_addr"]))
        if "dba" in gen:
            self.dba_expr_field.setText(gen["dba"])
        if "limit_values" in gen:
            self.values_limit_spinbox.setValue(gen['limit_values'])
        if "get_formula" in gen:
            self.get_formula_checkbox.setChecked(gen["get_formula"])
        if "from_addr" in gen:
            self.from_field.setText(hex(gen["from_addr"]))
        if "to_addr" in gen:
            self.to_field.setText(hex(gen["to_addr"]))
        if "restrict_values_from" in gen:
            self.restrict_from_field.setText(hex(gen["restrict_values_from"]))
        if "restrict_values_to" in gen:
            self.restrict_to_field.setText(hex(gen['restrict_values_to']))
        if "kind" in gen:
            if gen["kind"] == "VALUES":
                self.values_radiobutton.setChecked(True)
            else:
                self.satisfiability_radiobutton.setChecked(True)

    def serialize(self):
        from_field, to_field = self.from_field.text(), self.to_field.text()
        target_addr = self.target_addr_field.text()
        restrict_from, restrict_to = self.restrict_from_field.text(), self.restrict_to_field.text()
        try:
            if from_field != "":
                self.conf.from_addr = utils.to_addr(from_field)
            if to_field != "":
                self.conf.to_addr = utils.to_addr(to_field)
            if target_addr != "":
                self.conf.target_addr = utils.to_addr(target_addr)
            else:
                print "Target address is mandatory for generic analysis"
                return None
            if restrict_from != "":
                self.conf.restrict_values_from = utils.to_addr(restrict_from)
            if restrict_to != "":
                self.conf.restrict_values_to = utils.to_addr(restrict_to)
        except ValueError:
            print "Invalid values for either from/to or target address"

        dba_expr = self.dba_expr_field.text()
        if dba_expr == "":
            print "DBA Expr field must be filled !"
            return None
        else:
            self.conf.dba = dba_expr

        if self.satisfiability_radiobutton.isChecked():
            self.conf.kind = self.conf.SATISFIABILITY

        if self.values_radiobutton.isChecked():
            self.conf.kind = self.conf.VALUES
            self.conf.limit_values = self.values_limit_spinbox.value()

        if self.get_formula_checkbox.isChecked():
            self.conf.get_formula = True

        try:
            params = specific_parameters_t()
            params.typeid = params.GENERIC
            params.generic_params.CopyFrom(self.conf)
            return params
        except:
            print "Analysis specific arguments serialization failed"
            return None

    def from_button_clicked(self):
        self.from_field.setText(hex(idc.here()))

    def to_button_clicked(self):
        self.to_field.setText(hex(idc.here()))

    def restrict_from_button_clicked(self):
        self.restrict_from_field.setText(hex(idc.here()))

    def restrict_to_button_clicked(self):
        self.restrict_to_field.setText(hex(idc.here()))

    def target_addr_button_clicked(self):
        ea = idc.here()
        self.target_addr_field.setText(hex(ea))
        cmt = idc.RptCmt(ea)
        if cmt is not None:
            if cmt.startswith("//@assert:"):
                expr = cmt.split(":")[1].lstrip()
                self.dba_expr_field.setText(expr)

    @staticmethod
    def dba_help_button_clicked():
        s = '''
All the expression usable are:
- cst: val, val<size>, hexa
- var: eax, al ..
- load/store: @[addr], @[addr,size]
- unary: !e, -e
- binary: e1 bop e2
- restrict: {e, low, high}
- ite: if c e1 else e2

With:
- uop: [-, !(not)]
- bop: [+, -, *u, *s, /, /s, modu, mods, or, and, xor, >>(concat), lshift, rshiftu,
rshifts, lrotate, rrotate, =, <>, <=u, <u, >=u, >u, <=s, <s, >=s, >s, extu, exts]
        '''
        QtWidgets.QMessageBox.about(None, u"DBA langage help", unicode(s))

    def values_radiobutton_toggled(self, toggled):
        if toggled:
            self.set_visbility_stuff(True)
        else:
            self.set_visbility_stuff(False)

    def set_visbility_stuff(self, value):
        self.values_limit_spinbox.setVisible(value)
        self.restrict_label.setVisible(value)
        self.restrict_from_label.setVisible(value)
        self.restrict_from_field.setVisible(value)
        self.restrict_from_button.setVisible(value)
        self.restrict_to_label.setVisible(value)
        self.restrict_to_field.setVisible(value)
        self.restrict_to_button.setVisible(value)


# ================================= GENERIC ANALYSIS =================================
# ====================================================================================

class GenericAnalysis(DefaultAnalysis):

    config_widget = GenericAnalysisConfigWidget()
    name = "Generic"

    ANNOT_CODE = "Annotate code"
    HIGHLIGHT_CODE = "Highlight dependencies"
    GRAPH_DEPENDENCY = "Generate dependency graph"
    DISASS_UNKNOWN_TARGET = "Disassemble unknown targets"

    def __init__(self, parent, config, is_stream=False, trace=None):
        DefaultAnalysis.__init__(self, parent, config, is_stream, trace)
        self.results = GenericResults(config.additional_parameters.generic_params)
        self.result_widget = GenericAnalysisResultWidget(self)
        self.actions = {self.ANNOT_CODE:           (self.annotate_code, False),
                        self.HIGHLIGHT_CODE:       (self.highlight_dependency, False),
                        self.GRAPH_DEPENDENCY:      (self.graph_dependency, False),
                        self.DISASS_UNKNOWN_TARGET: (self.disassemble_new_targets, False)}
        self.addresses_lighted = set()
        self.backup_comment = {}
        self.formula = SMTFormula()

    def binsec_message_received(self, cmd, data):
        if cmd == ANALYSIS_RESULTS:
            print "Analysis results received !"
            self.results.parse(data)
        else:
            self.log(cmd, data, origin="BINSEC")

    def analysis_terminated(self):
        self.result_widget.post_analysis_stuff(self.results)
        if self.results.has_formula():
            self.formula.parse(self.results.formula)

    def annotate_code(self, enabled):
        if not enabled:  # Annotate
            s = ":["+self.results.get_status()+"]"
            if self.results.has_values():
                s += " vals:["+''.join(["%x," % x for x in self.results.values])[:-1] + "]"
            cmt = idc.RptCmt(self.results.target)
            if cmt != "":
                self.backup_comment[self.results.target] = cmt
                if cmt.startswith("//@assert"):
                    s = cmt + s
                else:
                    s = cmt + "\n" + self.results.query + s
            else:
                s = self.results.query + s
                self.backup_comment[self.results.target] = ""
            idc.MakeRptCmt(self.results.target, s.encode("utf-8", "ignore"))
        else:
            for addr, cmt in self.backup_comment.items():
                idc.MakeRptCmt(addr, cmt)
            self.backup_comment.clear()
        self.actions[self.ANNOT_CODE] = (self.annotate_code, not enabled)
        self.result_widget.action_selector_changed(self.ANNOT_CODE)

    def highlight_dependency(self, enabled):
        if self.results.has_formula():
            color = 0xffffff if enabled else 0x98FF98
            for addr in self.formula.get_addresses():
                idc.SetColor(addr, idc.CIC_ITEM, color)
        else:
            print "woot ?"
        self.actions[self.HIGHLIGHT_CODE] = (self.highlight_dependency, not enabled)
        self.result_widget.action_selector_changed(self.HIGHLIGHT_CODE)

    def graph_dependency(self, _):
        output = "/tmp/slice_rendered"
        self.formula.slice(output)
        res = subprocess.call(["dot", "-Tpdf", output, "-o", output+".pdf"])
        if res != 0:
            print "Something went wrong with dot"
        subprocess.Popen(["xdg-open", output+".pdf"])

    def disassemble_new_targets(self, _):
        for value in self.results.values:
            flag = idc.GetFlags(value)
            if not idc.isCode(flag) and idc.isUnknown(flag):
                res = idc.MakeCode(value)
                if res == 0:
                    print "Try disassemble at:"+hex(value)+" KO"
                    # TODO: Rollback ?
                else:
                    print "Try disassemble at:"+hex(value)+" Success !"


# ============================= RESULT WIDGET ===============================
# ===========================================================================
class GenericAnalysisResultWidget(QtWidgets.QWidget, Ui_generic_analysis_result):
    def __init__(self, parent):
        QtWidgets.QWidget.__init__(self)
        self.setupUi(self)
        self.parent = parent
        # self.result_area.setEnabled(False)
        if self.parent.results.get_formula:
            self.formula_label.setVisible(True)
            self.formula_area.setEnabled(True)
        else:
            self.formula_label.setVisible(False)
            self.formula_area.setVisible(False)
        self.action_selector.setEnabled(False)
        self.action_button.setEnabled(False)
        self.action_selector.addItem(self.parent.ANNOT_CODE)
        self.action_button.clicked.connect(self.action_clicked)
        self.action_selector.currentIndexChanged[str].connect(self.action_selector_changed)

    def action_selector_changed(self, s):
        _, enabled = self.parent.actions[s]
        if enabled:
            self.action_button.setText("Undo !")
        else:
            self.action_button.setText("Do !")

    def action_clicked(self):
        s = self.action_selector.currentText()
        fun, enabled = self.parent.actions[s]
        fun(enabled)

    def post_analysis_stuff(self, results):
        if results.has_formula():
            self.action_selector.addItem(self.parent.HIGHLIGHT_CODE)
            self.action_selector.addItem(self.parent.GRAPH_DEPENDENCY)
            self.formula_area.setText(self.parent.results.formula)
        if results.has_values():
            self.action_selector.addItem(self.parent.DISASS_UNKNOWN_TARGET)
        self.action_selector.setEnabled(True)
        self.action_button.setEnabled(True)

        report = HTMLReport()
        report.add_title("Results", size=3)
        report.add_table_header(["address", "assertion", "status", "values"])
        addr = make_cell("%x" % results.target)
        status = make_cell(results.get_status(), color=results.color, bold=True)
        vals = ""
        for value in results.values:
            flag = idc.GetFlags(value)
            typ = self.type_to_string(flag)
            vals += "%x type:%s seg:%s fun:%s<br/>" % (value, typ, idc.SegName(value), idc.GetFunctionName(value))
        report.add_table_line([addr, make_cell(cgi.escape(results.query)), status, make_cell(vals)])
        report.end_table()
        data = report.generate()
        self.result_area.setHtml(data)

    @staticmethod
    def type_to_string(t):
        if idc.isCode(t):
            return "C"
        elif idc.isData(t):
            return "D"
        elif idc.isTail(t):
            return "T"
        elif idc.isUnknown(t):
            return "Ukn"
        else:
            return "Err"

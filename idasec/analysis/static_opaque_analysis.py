# coding=utf-8
import time

from PyQt5 import QtCore, QtWidgets
from path import Path
import idc
import idaapi
import idautils

from idasec.commands import *
from idasec.proto.analysis_config_pb2 import specific_parameters_t
from idasec.proto.analysis_config_pb2 import po_analysis_results
from idasec.analysis.default_analysis import DefaultAnalysis, STATIC_AND_DYNAMIC
from idasec.widgets.StandardResultWidget import StandardResultWidget
from idasec.report_generator import make_cell, RED, GREEN, PURPLE, ORANGE, BLACK, HTMLReport
import idasec.utils as utils
from idasec.ida_utils import MyFlowGraph, get_succs, Status
from idasec.trace import make_header, chunk_from_path
from idasec.formula import *
from idasec.ui.static_iteration_config_ui import Ui_static_iteration_config


# =============================== CONFIGURATION =============================
# ===========================================================================
class StaticOpaqueConfigWidget(QtWidgets.QWidget, Ui_static_iteration_config):

    def __init__(self):
        super(StaticOpaqueConfigWidget, self).__init__()
        self.setupUi(self)
        self.horizontalLayout_2.setEnabled(False)
        self.radio_addr.toggled.connect(self.addr_radio_toggled)
        self.radio_routine.toggled.connect(self.routine_radio_toggled)
        self.radio_program.toggled.connect(self.program_radio_toggled)
        self.target_button.clicked.connect(self.target_button_clicked)
        self.radio_addr.setChecked(True)
        self.radio_path_routine.setChecked(True)

    def set_fields(self, json_fields):
        # Set the target field if a target is given in standard_params
        try:
            target = json_fields["standard_params"]["target_addr"]
            self.targetlineedit.setText(hex(target))
            self.radio_addr.setChecked(True)
        except KeyError:
            pass

    def serialize(self):
        s = str(self.target_field.text())
        if self.radio_addr.isChecked():
            try:
                int(s, 16)
            except ValueError:
                print "Bad address given"
                return None
        elif self.radio_routine.isChecked():
            addr = idc.LocByName(s)
            if addr == idc.BADADDR:
                print "Bad function name given"
                return None
        return specific_parameters_t()

    def addr_radio_toggled(self, enabled):
        if enabled:
            self.target_label.setText("Addr:")

    def routine_radio_toggled(self, enabled):
        if enabled:
            self.target_label.setText("Name:")

    def program_radio_toggled(self, enabled):
        self.target_label.setVisible(not enabled)
        self.target_field.setVisible(not enabled)
        self.target_button.setVisible(not enabled)

    def target_button_clicked(self):
        if self.radio_addr.isChecked():
            self.target_field.setText(hex(idc.here()))
        else:
            self.target_field.setText(idc.GetFunctionName(idc.here()))
# ================================================================================
# ================================================================================


# ==================== Data structures ==================
AddrRet = namedtuple("AddrRet", "status k dependency predicate distance alive_branch dead_branch")

cond_jump = ["jz", "jnz", "ja", "jae", "jnb", "jnc", "jb", "jc", "jbe", "jna", "je", "jne", "jg",
             "jge", "jnl", "jl", "jle", "jng"]


def to_status_name(x):
    return {po_analysis_results.UNKNOWN: "Unknown",
            po_analysis_results.NOT_OPAQUE: "Covered",
            po_analysis_results.OPAQUE: "Opaque",
            po_analysis_results.LIKELY: "Likely"}[x]


def status_to_color(x):
    return {po_analysis_results.UNKNOWN: PURPLE,
            po_analysis_results.LIKELY: ORANGE,
            po_analysis_results.NOT_OPAQUE: GREEN,
            po_analysis_results.OPAQUE: RED}[x]
# =======================================================


# ===================================== ANALYSIS =======================================
# ======================================================================================
# ANNOT_CODE = "Annotate opaque jumps"
# GENERATE_PLOT = "Generate plot chart"
HIGHLIGHT_DEAD_CODE = "Highlight dead code"
HIGHLIGHT_SPURIOUS_CALCULUS = "Highlight spurious computation"
EXPORT_RESULT = "Export results"
EXTRACT_REDUCED_CFG = "Extract reduced CFG"


class StaticOpaqueAnalysis(DefaultAnalysis):

    config_widget = StaticOpaqueConfigWidget()
    name = "static opaque"
    kind = STATIC_AND_DYNAMIC

    @staticmethod
    def on_analysis_selected(widget):
        print "Analyse selection changed !"
        index = widget.default_action_selector.findText("SYMB")
        widget.default_action_selector.setCurrentIndex(index)
        widget.direction_selector_changed("Backward")
        index = widget.policy_selector.findText("SS")
        widget.policy_selector.setCurrentIndex(index)
        # TODO Save somewhere the what was selected, and restore it

    def __init__(self, parent, config, is_stream=False, trace=None):
        DefaultAnalysis.__init__(self, parent, config, is_stream, trace)
        self.actions = {# ANNOT_CODE: (self.annotate_code, False),
                        # GENERATE_PLOT: (self.generate_chart, False),
                        HIGHLIGHT_DEAD_CODE: (self.highlight_dead_code, False),
                        HIGHLIGHT_SPURIOUS_CALCULUS: (self.highlight_spurious, False),
                        EXPORT_RESULT: (self.export_result, False),
                        EXTRACT_REDUCED_CFG: (self.extract_reduced_cfg, False)}
        self.results = {}
        self.result_widget = StandardResultWidget(self)
        self.result_widget.verticalLayout.addLayout(self.make_progress_bar(self.result_widget))
        self.STOP = False
        self.functions_cfg = {}
        self.functions_candidates = {}
        self.functions_spurious_instrs = {}
        self.po = po_analysis_results()
        self.k = -1
        self.report = HTMLReport()
        self.report.add_title("Opaque predicates Detection", size=2)
        self.exec_time_dep = 0
        self.exec_time_total = 0

    def run(self):
        # -- GUI stuff
        self.result_widget.set_actions_visible_and_enabled(False)
        self.set_progress_visible(True)
        # -----------

        # Refill the configuration file
        if self.configuration.ksteps != 0 and self.config_widget.radio_path_routine.isChecked():
            self.k = self.configuration.ksteps  # Use the ksteps given if making the path on the whole routine

        self.result_widget.webview.append("### Opaque predicates Detection ###\n")

        self.configuration.analysis_name = "static opaque"
        self.configuration.additional_parameters.typeid = self.configuration.additional_parameters.STANDARD

        target_val = str(self.config_widget.target_field.text())
        start_tps = time.time()
        if self.config_widget.radio_addr.isChecked():
            addr = utils.to_addr(target_val)
            self.process_routine(idaapi.get_func(addr).startEA, pred_addr=addr)
        elif self.config_widget.radio_routine.isChecked():
            addr = idc.LocByName(target_val)
            if addr == idc.BADADDR:
                addr = utils.to_addr(target_val)
            self.process_routine(addr)
        elif self.config_widget.radio_program.isChecked():
            self.process_program()
        else:
            pass

        self.exec_time_total = time.time() - start_tps - self.exec_time_dep
        self.analyse_finished = True
        self.broker.terminate()

        # -- GUI stuff
        self.result_widget.set_actions_visible_and_enabled(True)
        self.set_progress_visible(False)
        # ------------
        self.analysis_terminated()

    def process_program(self):
        funs = list(idautils.Functions())
        nb = len(funs)
        for i, fun in zip(xrange(nb), funs):
            self.process_routine(fun, rtn_i=i+1, total_rtn=nb)
            if self.STOP:
                return

    def process_routine(self, rtn_addr, pred_addr=None, rtn_i=1, total_rtn=1):
        if rtn_addr not in self.functions_cfg:
            self.functions_cfg[rtn_addr] = MyFlowGraph(rtn_addr)
        cfg = self.functions_cfg[rtn_addr]
        path_to = self.config_to_path_function(cfg)
        if pred_addr is None:
            candidates = {x for x in idautils.FuncItems(rtn_addr) if idc.GetMnem(x) in cond_jump}
        else:
            candidates = {pred_addr}
        nb_candidates = len(candidates)
        self.functions_candidates[rtn_addr] = set()
        self.functions_spurious_instrs[rtn_addr] = set()

        self.progressbar_loading.reset()
        self.progressbar_loading.setMaximum(len(candidates))

        name = idc.GetFunctionName(rtn_addr)
        self.result_widget.webview.append("\n=> Function:%s\n" % name)

        self.log("[result]", "Start processing function: 0x%x" % rtn_addr)
        for i, addr in zip(xrange(len(candidates)), candidates):
            path = path_to(addr)
            res = self.process_addr(rtn_addr, addr, path)
            if self.STOP:
                return
            elif res is None:
                continue
            dead_br = "/" if res.dead_branch is None else "%x" % res.dead_branch
            self.result_widget.webview.append("%x:\t%s\t\tK:%d\tDead:%s" % (addr, to_status_name(res.status), res.k, dead_br))

            self.result_widget.webview.verticalScrollBar().setValue(self.result_widget.webview.verticalScrollBar().maximum())
            self.loading_stat.setText("Fun: %d/%d  Addr: %d/%d" % (rtn_i, total_rtn, i+1, nb_candidates))

            self.progressbar_loading.setValue(self.progressbar_loading.value()+1)
            self.functions_candidates[rtn_addr].add(addr)

    def process_addr(self, rtn_addr, addr, path, rec=5):
        succs = get_succs(addr)
        if len(succs) > 2:
            print "Addr: %x have more than two sucessors" % addr
            return

        k = len(path) if self.k == -1 else self.k
        self.configuration.ksteps = k
        self.configuration.additional_parameters.standard_params.target_addr = addr
        self.configuration.additional_parameters.standard_params.get_formula = True

        for res in self.send_query_binsec(self.configuration, path[-k:], addr):
            self.po.ParseFromString(res)
            if len(self.po.values) != 1:
                print "Wrong number of results for %x: %d" % (addr, len(self.po.values))
            else:
                po = self.po.values[0]
                before = time.time()
                formula_dep, predicate, distance = self.compute_dependency_and_predicate(po.formula) if po.formula else ([], "", 0)
                # formula_dep, predicate, distance = ([], "", 0)
                self.exec_time_dep += time.time() - before
                dead_branch = [x for x in succs if x != po.alive_branch][0] if po.status == self.po.OPAQUE else None
                if po.status == self.po.OPAQUE:
                    self.functions_spurious_instrs[rtn_addr].update(formula_dep+[addr])
                self.results[addr] = AddrRet(po.status, k, formula_dep, predicate, distance, po.alive_branch, dead_branch)
        # print "End processing address:%x status:%s" % (addr, to_status_name(ret.status))
        if addr in self.results:
            return self.results[addr]
        else:
            if self.STOP or rec == 0:  # The timeout was probably triggered
                print("Ignore %x" % addr)
                return None
            else:
                print("Restart: %x" % addr)
                self.process_addr(rtn_addr, addr, path, rec=rec-1)

    def send_query_binsec(self, conf, path, addr):
        self.broker.send_binsec_message(START_ANALYSIS, conf.SerializeToString())
        header = make_header().SerializeToString()
        chunk = chunk_from_path(path).SerializeToString()
        # self.dump_trace(header, chunk, addr)
        self.broker.send_binsec_message(TRACE_HEADER, header)
        self.broker.send_binsec_message(TRACE_CHUNK, chunk)
        self.broker.send_binsec_message(END, EMPTY)
        before = time.time()+10
        for origin, cmd, data in self.broker.run_broker_loop_generator():
            QtWidgets.QApplication.processEvents()

            if self.STOP:
                break

            if origin == BINSEC:
                if cmd == "END":
                    break
                elif cmd == ANALYSIS_RESULTS:
                    yield data
                else:
                    if data.find("Not decoded") == data.find("Undecoded instr") == -1:
                        self.log(cmd, data)
            elif origin is None and time.time() > before:
                print "Timeout over !"
                break

    @staticmethod
    def dump_trace(header, chunk, addr):
        import struct
        f = open("/tmp/%x.dmp" % addr, "wb")
        f.write(struct.pack("I", len(header)))
        f.write(header)
        f.write(struct.pack("I", len(chunk)))
        f.write(chunk)
        f.close()

    def compute_dependency_and_predicate(self, raw_formula):
        f = SMTFormula()
        f.parse(raw_formula)
        offsets, bin_op, distance = self.slice(f)
        pred = self.expr_synthesis(bin_op) if bin_op else u""
        # print "compute_dependency: ", pred, offsets #,"\n",bin_op
        return offsets, pred, distance

    def config_to_path_function(self, cfg):
        if self.config_widget.radio_path_routine.isChecked():
            return cfg.full_path_to
        elif self.config_widget.radio_path_basicblock.isChecked():
            return cfg.bb_path_to
        elif self.config_widget.radio_path_safe.isChecked():
            return cfg.safe_path_to
        else:
            assert False

    def analysis_terminated(self):
        self.log("[info]", "Analysis %s terminated" % self.name)

        self.refine_results()
        # self.compute_dead_code()
        self.propagate_liveness()
        self.generate_opaqueness_stats_report()
        self.generate_dead_code_stats_report()
        self.generate_opaqueness_details_report()
        # TODO: Stat of pattern used etc..

        self.result_widget.webview.setHtml(self.report.generate())

    def refine_results(self):
        likely_retag = 0
        fp_retag = 0
        fn_retag = 0
        for rtn_addr, candidates in self.functions_candidates.items():
            for addr in sorted(candidates):
                res = self.results[addr]
                val = sum([x in res.predicate for x in ["(0 :: 2)", "7x", "7y", u"²"]])
                final_status = res.status
                alive, dead = res.alive_branch, res.dead_branch
                if res.status == self.po.NOT_OPAQUE:
                    if val != 0:
                        fn_retag += 1
                        final_status = self.po.OPAQUE
                        jmp_target = [x for x in idautils.CodeRefsFrom(addr, 0)][0]
                        next_target = [x for x in idautils.CodeRefsFrom(addr, 1) if x != jmp_target][0]
                        alive, dead = (next_target, jmp_target) if idc.GetDisasm(addr)[:2] == "jz" else (jmp_target, next_target)
                        self.functions_spurious_instrs[rtn_addr].update(res.dependency+[addr])
                elif res.status == self.po.OPAQUE:
                    if val == 0:
                        fp_retag += 1
                        final_status = self.po.NOT_OPAQUE
                elif res.status == self.po.LIKELY:
                    if val == 0:
                        final_status = self.po.NOT_OPAQUE
                    else:
                        final_status = self.po.OPAQUE
                        jmp_target = [x for x in idautils.CodeRefsFrom(addr, 0)][0]
                        next_target = [x for x in idautils.CodeRefsFrom(addr, 1) if x != jmp_target][0]
                        alive, dead = (next_target, jmp_target) if idc.GetDisasm(addr)[:2] == "jz" else (jmp_target, next_target)
                        self.functions_spurious_instrs[rtn_addr].update(res.dependency+[addr])
                    likely_retag += 1
                self.results[addr] = AddrRet(final_status, res.k, res.dependency, res.predicate, res.distance, alive, dead)
        print "Retag: FP->OK:%d" % fp_retag
        print "Retag: FN->OP:%d" % fn_retag
        print "Retag: Lkl->OK:%d" % likely_retag

    def generate_opaqueness_stats_report(self):
        self.report.add_title('Stats opaqueness', size=3)
        self.report.add_table_header(["type", "number", "percentage"])
        total = len(self.results)
        for state in [self.po.OPAQUE, self.po.NOT_OPAQUE, self.po.UNKNOWN]:
            nb = len([x for x in self.results.values() if x.status == state])
            avg = float(nb*100)/(total if total != 0 else 1)
            state_cell = make_cell(to_status_name(state), bold=True, color=status_to_color(state))
            self.report.add_table_line([state_cell, make_cell(str(nb)), make_cell("%d%c" % (avg, '%'))])
        self.report.end_table()

    def generate_dead_code_stats_report(self):
        stats = {"DEAD": 0, "ALIVE": 0, "SPURIOUS": 0, "UNKNOWN": 0}
        to_color = {"DEAD": RED, "ALIVE": GREEN, "SPURIOUS": ORANGE, "UNKNOWN": BLACK}
        for cfg in self.functions_cfg.values():
            for bb in cfg.values():
                if bb.is_dead():
                    stats["DEAD"] += bb.size()
                elif bb.is_unknown():
                    stats["UNKNOWN"] += bb.size()
                elif bb.is_alive():
                    for i, st in bb.instrs_status.items():
                        if st == Status.ALIVE:
                            stats["ALIVE"] += 1
                        elif st == Status.DEAD:
                            stats["SPURIOUS"] += 1
                        else:
                            stats["UNKNOWN"] += 1
        self.report.add_title('Stats Dead Code', size=3)
        self.report.add_table_header(["type", "number", "percentage"])
        total = sum(stats.values())
        for st, nb in stats.items():
            avg = float(nb*100)/(total if total != 0 else 1)
            self.report.add_table_line([make_cell(st, color=to_color[st]), make_cell(str(nb)), make_cell("%d%c" % (avg, '%'))])
        self.report.end_table()

    def generate_opaqueness_details_report(self):
        for rtn_addr, candidates in self.functions_candidates.items():
            self.report.add_title('%s' % idc.GetFunctionName(rtn_addr), size=3)
            self.report.add_table_header(['address', "status", "K", "predicate", "distance", "dead branch"])
            for addr in sorted(candidates):
                res = self.results[addr]
                status, color = to_status_name(res.status), status_to_color(res.status)
                status = make_cell(status, bold=True, color=color)
                dead_br_cell = make_cell("/" if res.dead_branch is None else "%x" % res.dead_branch)
                self.report.add_table_line([make_cell("%x" % addr), status, make_cell(str(res.k)), make_cell(res.predicate), make_cell(str(res.distance)), dead_br_cell])
            self.report.end_table()

    def propagate_liveness(self):
        for fun_addr, cfg in self.functions_cfg.items():
            candidates = self.functions_candidates[fun_addr]
            spurious = self.functions_spurious_instrs[fun_addr]
            worklist = [cfg[0]]
            while worklist:
                bb = worklist.pop()
                if bb.status == Status.UNKNOWN:
                    # print "%d 0x%x marked ALIVE" % (bb.id, bb.startEA)
                    bb.status = Status.ALIVE
                    last = bb.last()
                    succs = list(bb.succs())
                    if last in candidates:
                        infos = self.results[last]
                        if infos.status == self.po.OPAQUE:
                            succ = [x for x in succs if x.startEA == infos.alive_branch][0]
                            # print "Append %x to worklist" % succ.startEA
                            worklist.append(succ)
                        else:
                            # print "Append all child to worklist"
                            worklist.extend(succs)
                    else:  # Just propagate normally
                        # print "last 0x%x not in candidates" % last
                        worklist.extend(succs)

                    for i in bb:  # Update the status for instructions
                        st = Status.DEAD if i in spurious else Status.ALIVE
                        bb.set_instr_status(i, st)

            for bb in [x for x in cfg.values() if x.status == Status.UNKNOWN]:
                bb.status = Status.DEAD

    # -- Action handlers
    def annotate_code(self, _):
        print "Annotate code !"

    def generate_chart(self, _):
        print "Generate chart !"

    def highlight_dead_code(self, enabled):
        curr_fun = idaapi.get_func(idc.here()).startEA
        cfg = self.functions_cfg[curr_fun]
        # for cfg in self.functions_cfg.values():
        for bb in cfg.values():
            color = {Status.DEAD: 0x5754ff, Status.ALIVE: 0x98FF98, Status.UNKNOWN: 0xaa0071}[bb.status]
            color = 0xFFFFFF if enabled else color
            for i in bb:
                idc.SetColor(i, idc.CIC_ITEM, color)
        self.actions[HIGHLIGHT_DEAD_CODE] = (self.highlight_dead_code, not enabled)
        self.result_widget.action_selector_changed(HIGHLIGHT_DEAD_CODE)

    def highlight_spurious(self, enabled):
        print "Highlight spurious clicked !"
        curr_fun = idaapi.get_func(idc.here()).startEA
        cfg = self.functions_cfg[curr_fun]
        color = 0xFFFFFF if enabled else 0x507cff
        for bb in [x for x in cfg.values() if x.is_alive()]:  # Iterate only alive basic blocks
            for i, st in bb.instrs_status.items():
                if st == Status.DEAD:  # Instructions dead in alive basic blocks are spurious
                    idc.SetColor(i, idc.CIC_ITEM, color)
        self.actions[HIGHLIGHT_SPURIOUS_CALCULUS] = (self.highlight_spurious, not enabled)
        self.result_widget.action_selector_changed(HIGHLIGHT_SPURIOUS_CALCULUS)

    def export_result(self, _):
        filename = QtWidgets.QFileDialog.getSaveFileName()[0]
        filepath = Path(filename)
        if not filepath.exists() and filepath != '':
                report = filepath if filepath.ext == ".html" else filepath.dirname() / filepath.namebase+".html"
                raw = filepath.dirname() / filepath.namebase+".csv"
                html_file = filepath.dirname() / filepath.namebase+".html"
                html_file.write_bytes(self.report.generate())
                report.write_text(self.report.generate())
                f = raw.open("w")
                for addr, infos in self.results.iteritems():
                    f.write_bytes(u"0x%x,%s,%d,%s,0x%x,0x%x\n" % (addr, to_status_name(infos.status), infos.k,
                                                            infos.dependency, infos.alive_branch, infos.dead_branch))
                f.close()
                self.log("[info]", "Export done in %s and %s" % (report.basename(), raw.basename()))
        else:
            self.log("[error]", "File already exists.. (do not save)")


    def extract_reduced_cfg(self, _):
        # TODO: Make a copy of the CFG before stripping it
        print "Extract reduced CFG"
        curr_fun = idaapi.get_func(idc.here()).startEA
        cfg = self.functions_cfg[curr_fun]
        po_addrs = {k for k, v in self.results.items() if v.status == self.po.OPAQUE}

        cfg.remove_dead_bb()  # Dead basic block removal step

        # Relocation + Merge step
        for idx, bb in cfg.items():
            print "try reduce: %d: 0x%x" % (idx, bb.startEA)
            if bb.is_full_spurious() and bb.nb_preds() == bb.nb_succs() == 1:  # Do relocation
                bb_pred = list(bb.preds())[0]
                bb_succ = list(bb.succs())[0]
                print "  relocation bind %d->%d" % (bb_pred.id, bb_succ.id)
                bb_pred.remove_succ(bb)
                bb_pred.add_succ(bb_succ)
                bb_succ.remove_pred(bb)
                bb_succ.add_pred(bb_pred)
                cfg.pop(idx)
            elif not(bb.is_full_spurious()):
                if bb.nb_preds() == 1:
                    bb_pred = list(bb.preds())[0]
                    print "  One pred! %d, 0x%x" % (bb_pred.nb_succs(), bb_pred.last())
                    if bb_pred.nb_succs() == 1 and bb_pred.last() in po_addrs:
                        bb_pred.concat(bb)
                        cfg.pop(idx)
            else:
                print "  None of all ?"
        cfg.Show()

    def stop_button_clicked(self):
        self.STOP = True

    def set_progress_visible(self, enable):
        self.loading_stat.setVisible(enable)
        self.progressbar_loading.setVisible(enable)
        self.stop_button.setVisible(enable)

    def make_progress_bar(self, parent):
        horizontalLayout_2 = QtWidgets.QHBoxLayout()
        horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.loading_stat = QtWidgets.QLabel(parent)
        horizontalLayout_2.addWidget(self.loading_stat)
        self.progressbar_loading = QtWidgets.QProgressBar(parent)
        horizontalLayout_2.addWidget(self.progressbar_loading)
        self.stop_button = QtWidgets.QPushButton(parent)
        self.stop_button.setMaximumSize(QtCore.QSize(50, 30))
        self.stop_button.setText("stop")
        horizontalLayout_2.addWidget(self.stop_button)
        self.stop_button.clicked.connect(self.stop_button_clicked)
        return horizontalLayout_2

    def replace_var_bv_expr(self, name, sub, e, arr, pld):
        if isinstance(e, Bv):
            return e
        elif isinstance(e, Var):
            return sub if e.name == name else e
        elif isinstance(e, UnOp):
            return UnOp(e.op, self.replace_var_bv_expr(name, sub, e.expr, arr, pld), e.opt1, e.opt2)
        elif isinstance(e, BinOp):
            return BinOp(e.op, self.replace_var_bv_expr(name, sub, e.expr1, arr, pld),
                         self.replace_var_bv_expr(name, sub, e.expr2, arr, pld))
        elif isinstance(e, Ite):
            c1 = self.replace_var_bv_expr(name, sub, e.cond, arr, pld)
            e1 = self.replace_var_bv_expr(name, sub, e.expr1, arr, pld)
            e2 = self.replace_var_bv_expr(name, sub, e.expr2, arr, pld)
            return Ite(c1, e1, e2)
        elif isinstance(e, Select) or isinstance(e, Select32):
            if e.expr in arr:
                return arr[e.expr]
            else:
                new_v = pld.pop(0)  # TODO: HERE !
                arr[e.expr] = Var(new_v)
                return Var(new_v)
        else:
            print "Unknown type", type(e)
            return e

    def slice(self, f):
        cmp_found = False
        var_seen = set()
        off_to_keep = {}
        bin_op = None
        tmp_arr = {}
        bag = ['y', 'x', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm']
        for off in reversed(sorted(f.formula.keys())):
            # print "Offset ", off, ": ",
            if not cmp_found:
                if off == -1:
                    break
                mnemonic = f.offset_instr[off][1]
                if mnemonic[:4] in ["cmp ", "test", "sub "]:
                    # print "Found cmp %d: %s" % (off, f.offset_instr[off][1])
                    cmp_found = True
                    vars = set(f.get_var_bv_expr(f.formula[off][0].value))
                    # print "vars found", vars
                    if len(vars) != 2:
                        # print "No two variables were found abort %s", vars
                        break
                    var_seen.update(vars)
                    off_to_keep[off] = [0]
                    bin_op = BinOp("bvcomp", Var(vars.pop()), Var(vars.pop()))
                else:
                    continue
            else:  # Normal case
                cmds = f.formula[off]
                for i, vardef in reversed(zip(xrange(len(cmds)), cmds)):
                    try:
                        name, expr = vardef.name, vardef.value
                        if name in var_seen:
                            var_seen.remove(name)
                            vars = f.get_var_bv_expr(expr)
                            # print name, " found vars:", vars
                            var_seen.update(vars)
                            off_to_keep[off] = off_to_keep.get(off, [])+[i]
                            bin_op = self.replace_var_bv_expr(name, expr, bin_op, tmp_arr, bag)
                        else:
                            pass  # print name, " does not belong to var_seen"
                    except AttributeError:
                        pass
                if not var_seen:  # Means empty
                    break
        bin_op = self.replace_var_bv_expr("stub", "stub", bin_op, tmp_arr, bag) if bin_op is not None else None
        addr_dep = [v[0] for k, v in f.offset_instr.items() if k in off_to_keep]
        distance = max(off_to_keep)-min(off_to_keep)+1 if len(off_to_keep) != 0 else 0
        return addr_dep, bin_op, distance

    def expr_synthesis(self, e, top=True):
        o, r = ("(", ")") if not top else ("", "")
        if isinstance(e, Bv):
            return e.value
        elif isinstance(e, Var):
            return e.name
        elif isinstance(e, UnOp):
            if e.op in ["zero_extend", "sign_extend"]:
                return self.expr_synthesis(e.expr, False)
            elif e.op == "extract":
                s = self.expr_synthesis(e.expr, True)
                return u"(%s){%s,%s}" % (s, e.opt2, e.opt1) if not top else s
            else:
                return u"(%s %s)" % (e.op, self.expr_synthesis(e.expr, False))
        elif isinstance(e, BinOp):
            if e.op == "bvmul" and e.expr1 == e.expr2:
                return u"%s²" % (self.expr_synthesis(e.expr1, True))
            elif e.op == "bvxor" and e.expr1 == e.expr2:
                return u"0"
            elif e.op == "bvmul" and isinstance(e.expr2, Bv):
                return u"%s%s" % (e.expr2.value, self.expr_synthesis(e.expr1, False))
            else:
                top = e.op == "bvcomp" and top
                return u"%s%s %s %s%s" % (o, self.expr_synthesis(e.expr1, top), SMTFormula.bop_to_pp_string(e.op),
                                          self.expr_synthesis(e.expr2, top), r)
        elif isinstance(e, Ite):
            c = self.expr_synthesis(e.cond, False)
            e1 = self.expr_synthesis(e.expr1, False)
            e2 = self.expr_synthesis(e.expr2, False)
            return u"%s%s ? %s: %s%s" % (o, c, e1, e2, r)
        else:
            return u"[n/a]"

    def generate_dead_alive_dump(self):
        f = Path("dead_or_alive_dump.txt")
        handle = f.open("w")
        for cfg in self.functions_cfg.values():
            for bb in cfg.values():
                for i in bb.instrs:
                    status = bb.instrs_status[i] if bb.is_alive() else Status.DEAD
                    size = idc.NextHead(i)-i
                    handle.write(u"%x,%d,%s\n" % (i, size, status))
        handle.close()

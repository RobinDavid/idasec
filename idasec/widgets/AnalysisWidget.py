# coding: utf8

import time
import base64

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QTableWidgetItem, QComboBox, QInputDialog, QMessageBox, QFileDialog

from idasec.ui.custom_widgets import ButtonLineEdit
from idasec.analysis.default_analysis import STATIC, DYNAMIC, STATIC_AND_DYNAMIC

import json
from idasec.protobuf_json import json2pb, pb2json
from idasec.path import Path
from idasec.proto.config_pb2 import configuration, input_t
import idasec.proto.common_pb2 as common_pb2
import idasec.proto.libcall_pb2 as libcall_pb2
import idasec.proto.syscall_pb2 as syscall_pb2
import idasec.proto.instruction_pb2 as instruction_pb2
from idasec.utils import register_name_to_size, hex_to_bin, to_hex

import idc
import idautils

import idasec.ui.resources_rc

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

class AnalysisWidget(QtWidgets.QWidget):
    def __init__(self, parent):
        super(AnalysisWidget, self).__init__()
        self.parent = parent
        self.name = "AnalysisWidget"
        self.core = self.parent.core

        # -- Internal structures
        self.libcalls = ["printf", "strcpy", "atoi", "malloc", "GetModuleHandle", "GetProcAddress"]
        self.syscalls = []
        self.instructions = ["cpuid"]
        self.start = None
        self.stop = None
        # ----------------------

        self.OnCreate()

    def OnCreate(self):
        self.setupUi(self)

        # --- Visibility stuff
        self.analysis_specific_group.setVisible(False)
        self.remote_radiobutton.setVisible(False)
        self.local_radiobutton.setChecked(True)
        self.start_entrypoint_checkbox.setVisible(False)
        self.trace_waves_checkbox.setVisible(False)
        self.antidebug_checkbox.setVisible(False)
        self.k_label.setVisible(False)
        self.k_spinbox.setVisible(False)

        # --- Initialize input table
        self.input_header_table = ["type", "where", "addr/name", "value", "action", "when"]
        self.inputs_table.setColumnCount(len(self.input_header_table))
        self.inputs_table.setHorizontalHeaderLabels(self.input_header_table)
        self.inputs_table.horizontalHeader().setStretchLastSection(True)
        self.inputs_table.horizontalHeader().sectionResizeMode(self.inputs_table.horizontalHeader().ResizeToContents)
        self.inputs_table.keyPressEvent = self.input_item_keypressed
        self.initial_state_list.keyPressEvent = self.initial_state_keypressed

        # --- Initialize policy table
        self.policy_header_table = ["loc", "inst", "exp", u"Σ", u"ρ"]
        self.policy_table.setColumnCount(len(self.policy_header_table))
        self.policy_table.setHorizontalHeaderLabels(self.policy_header_table)
        self.policy_table.horizontalHeader().sectionResizeMode(self.policy_table.horizontalHeader().ResizeToContents)

        # --- Fill some Widgets
        #self.analysis_name_selector.addItems(self.core.analyses.keys())
        self.direction_selector.addItems(["Forward", "Backward"])
        self.callcvt_selector.addItems(["cdecl", "stdcall", "fastcall","thiscall"])
        self.policy_selector.addItems(["Custom", "CC", "CS", "SC", "SSe", "SS"])
        self.default_action_selector.addItems(["CONC", "SYMB"])
        self.solver_selector.addItems(["auto"])

        # --- Initialize events
        self.add_input_button.clicked.connect(self.add_input_action)
        self.add_initial_state_button.clicked.connect(self.add_initial_state_action)
        self.add_bp_button.clicked.connect(self.add_bp_action)
        self.remove_bp_button.clicked.connect(self.remove_bp_action)
        self.detect_start_button.clicked.connect(self.detect_start_action)
        self.detect_stop_button.clicked.connect(self.detect_stop_action)
        self.analysis_name_selector.currentIndexChanged.connect(self.analysis_name_changed)
        self.direction_selector.currentIndexChanged.connect(self.direction_selector_changed)
        self.local_radiobutton.toggled.connect(self.local_radiobutton_toggled)
        self.policy_selector.currentIndexChanged.connect(self.policy_selector_changed)
        self.add_policy_item_button.clicked.connect(self.add_policy_item_action)
        self.remove_policy_item_button.clicked.connect(self.remove_policy_item_action)
        self.help_policy_button.clicked.connect(self.help_policy_action)
        self.add_libcall_button.clicked.connect(self.add_libcall_action)
        self.remove_libcall_button.clicked.connect(self.remove_libcall_action)
        self.add_syscall_button.clicked.connect(self.add_syscall_action)
        self.remove_syscall_button.clicked.connect(self.remove_syscall_action)
        self.add_instruction_button.clicked.connect(self.add_instr_action)
        self.remove_instruction_button.clicked.connect(self.remove_instr_action)
        self.save_config_button.clicked.connect(self.save_config_clicked)
        self.load_config_button.clicked.connect(self.load_config_clicked)
        self.generate_config_button.clicked.connect(self.generate_config_clicked)
        self.trigger_analysis_button.clicked.connect(self.trigger_analysis_clicked)

    def add_input_action(self):
        self.inputs_table.setRowCount(self.inputs_table.rowCount()+1)
        i = self.inputs_table.rowCount()-1
        type_combo = QComboBox()
        type_combo.addItems(["REG", "MEM"])
        action_combo = QComboBox()
        action_combo.addItems(["DEFAULT", "PATCH", "CONC", "SYMB", "IGNORE"])
        when_combo = QComboBox()
        when_combo.addItems(["BEFORE", "AFTER"])
        info = [type_combo, QTableWidgetItem(), QTableWidgetItem(), QTableWidgetItem(), action_combo, when_combo]

        for col_id, widget in enumerate(info):
            if isinstance(widget, QTableWidgetItem):
                self.inputs_table.setItem(i, col_id, widget)
            else:
                self.inputs_table.setCellWidget(i, col_id, widget)
        return i


    def input_item_keypressed(self, event):
        if event.key() == QtCore.Qt.Key_Delete:
            self.inputs_table.removeRow(self.inputs_table.currentRow())
        return QtWidgets.QTableWidget.keyPressEvent(self.inputs_table, event)

    def add_initial_state_action(self):
        from_addr = self.initial_state_from_field.text()
        to_addr = self.initial_state_to_field.text()
        if from_addr == "" or to_addr == "":
            print "One of the two fields from/to is empty"
            return
        try:
            from_addr = int(from_addr, 16)
            to_addr = int(to_addr, 16)
            if to_addr <= from_addr:
                print "'To' address must be strictly superior than 'from'"
            else:
                raw = base64.b64encode(idc.GetManyBytes(from_addr,to_addr-from_addr+1))
                self.initial_state_list.addItem("%x -> %x: %s" %(from_addr, to_addr, raw))
        except ValueError:
            print "From or To cannot be converted to address"

    def initial_state_keypressed(self, event):
        if event.key() == QtCore.Qt.Key_Delete:
            it = self.initial_state_list.takeItem(self.initial_state_list.currentRow())
            del it
        return QtWidgets.QListWidget.keyPressEvent(self.initial_state_list, event)

    def add_bp_action(self):
        res = idc.AskAddr(idc.here(), "Breakpoint address:")
        #value, ok = QInputDialog.getText(self, "Add breakpoint", "Breakpoint address:")
        if res is not None:
            self.bp_list.addItem(hex(res))
        else:
            print "Invalid breakpoint entered!"

    def remove_bp_action(self):
        self.bp_list.removeItem(self.bp_list.currentIndex())

    def detect_start_action(self):
        if self.start is None:
            self.detect_start_and_stop()
        self.start_field.setText(hex(self.start))

    def detect_stop_action(self):
        if self.stop is None:
            self.detect_start_and_stop()
        self.stop_field.setText(hex(self.stop))

    def detect_start_and_stop(self):
        start, stop = 0, 0
        if self.core.ftype == "PE":
            start, stop = self.core.fun_mapping["start"]
        else:
            if self.core.fun_mapping.has_key("main"):
                start, stop = self.core.fun_mapping["main"]
            elif self.core.fun_mapping.has_key("start"):
                if self.core.fun_mapping.has_key("__libc_start_main"):
                    instrs = list(idautils.FuncItems(self.core.fun_mapping["start"][0]))
                    instrs.reverse()
                    for inst in instrs:
                        arg1 = idc.GetOperandValue(inst, 0)
                        fname = idc.GetFunctionName(arg1)
                        if idc.GetMnem(inst) == "push":
                            start, stop = arg1, self.core.fun_mapping["start"][1]
                            break
                else:
                    start, stop = self.core.fun_mapping["start"]
            else:
                start, stop = idc.BeginEA(), 0
        self.start, self.stop = start, stop

    def analysis_name_changed(self, name):
        analysis_class = self.parent.analysis_from_name(name)
        if analysis_class.config_widget is not None:
            self.analysis_specific_group.setVisible(True)
            for cnt in range(self.analysis_specific_layout.count()):
                item = self.analysis_specific_layout.itemAt(cnt)
                item.widget().hide()
                self.analysis_specific_layout.removeItem(item)
            analysis_class.config_widget.show()
            self.analysis_specific_layout.addWidget(analysis_class.config_widget)
            try:
                names = ["GENERIC", "CALLRET", "OPAQUE", "STATIC OPAQUE"]
                name = names[name]
            except:
                pass
            self.analysis_specific_group.setTitle(name+" configuration")
            analysis_class.on_analysis_selected(self) # Allow the analysis to perform some processing on the widget
        else:
            self.analysis_specific_group.setVisible(False)

    def direction_selector_changed(self, name):
        try:
            names = ["Forward", "Backward"]
            name = names[name]
        except:
            pass            

        if self.direction_selector.currentText() != name:
            self.direction_selector.setCurrentIndex(self.direction_selector.findText(name))

        if name == "Forward":
            self.k_label.setVisible(False)
            self.k_spinbox.setVisible(False)
        elif name == "Backward":
            self.k_label.setVisible(True)
            self.k_spinbox.setVisible(True)
        else:
            print "woot ?"

    def local_radiobutton_toggled(self, toggled):
        if toggled:
            self.trace_label.setVisible(True)
            self.trace_selector.setVisible(True)
        else:
            self.trace_label.setVisible(False)
            self.trace_selector.setVisible(False)

    def policy_selector_changed(self, name):
        self.policy_table.clearContents()
        self.policy_table.setRowCount(0)
        if name == "Custom":
            pass
        else:
            mapping = {"CC": [["*", "@[?a] := _", "!a", "*", "C"],
                             ["*", "_ := ?e", "@[!$$] <: !e", "*", "C"],
                             ["*", "goto ?e", "@[!$$] <: !e", "*", "C"],
                             ["default", "", "", "", "P"]],
                       "CS": [["*", "_ := ?e", "@[!$$] <: !e", "*", "C"],
                              ["*", "goto ?e", "@[!$$] <: !e", "*", "C"],
                              ["*", "*", "esp", "*", "Pc"],
                              ["*", "*", "ebp", "*", "Pc"],
                              ["default", "", "", "", "Ps"]],
                       "SC": [["*", "@[?a] := _", "!a", "*", "C"],
                              ["default", "", "", "", "Ps"]],
                       "SSe":[["*", "*", "esp", "*", "Pc"],
                              ["*", "*", "ebp", "*", "Pc"],
                              ["default", "", "", "", "P"]],
                       "SS": [["default", "", "", "", "P"]]}      
            try:
                names = ["CC", "CS", "SC", "SSe", "SS"]
                name = names[name-1]
            except:
                pass

            for line in mapping[name]:
                i = self.add_policy_item_action()
                self.set_policy_item_values(i, line)

    def add_policy_item_action(self):
        self.policy_table.setRowCount(self.policy_table.rowCount()+1)
        i = self.policy_table.rowCount()-1
        btn1 = ButtonLineEdit(['*', "'addr'", "[addr1..addr2]","default"])
        btn2 = ButtonLineEdit(["*", " _ := _", "goto _"])
        btn3 = ButtonLineEdit(["*", "expr", "expr1 <: expr2"])
        btn4 = ButtonLineEdit(["*", "istainted(_)", "term1 && term2", "term1 || term2"])
        btn5 = QComboBox()
        btn5.addItems(["C", "P", "Pc", "Ps", "S"])
        for col_id, widget in enumerate([btn1, btn2, btn3, btn4, btn5]):
            self.policy_table.setCellWidget(i, col_id, widget)
        return i

    def set_policy_item_values(self, i,  values):
        for cold_id, v in enumerate(values):
            if cold_id == len(values)-1:
                q = self.policy_table.cellWidget(i, cold_id)
                q.setCurrentIndex(q.findText(v))
            else:
                self.policy_table.cellWidget(i, cold_id).setText(v)

    def remove_policy_item_action(self):
        self.policy_table.removeRow(self.policy_table.currentRow())

    def help_policy_action(self):
        QMessageBox.about(self, u"Policy help", u"Nothing into yet..")


    def add_libcall_action(self):
        already_added = [self.libcall_selector.itemText(x) for x in xrange(self.libcall_selector.count())]
        items = [x for x in self.libcalls if x not in already_added]
        if len(items)==0:
            print "Nothing else to add"
        else:
            lib, ok = QInputDialog.getItem(self, "Libcall selector", "Libcall stub to add:", items)
            if ok:
                self.libcall_selector.addItem(lib)

    def remove_libcall_action(self):
        self.libcall_selector.removeItem(self.libcall_selector.currentIndex())

    def add_syscall_action(self):
        already_added = [self.syscall_selector.itemText(x) for x in xrange(self.syscall_selector.count())]
        items = [x for x in self.syscalls if x not in already_added]
        if len(items) == 0:
            print "Nothing else to add"
        else:
            sys, ok = QInputDialog.getItem(self, "Syscall selector", "Syscall stub to add:", items)
            if ok:
                self.syscall_selector.addItem(sys)

    def remove_syscall_action(self):
        self.syscall_selector.removeItem(self.syscall_selector.currentIndex())

    def add_instr_action(self):
        already_added = [self.instruction_selector.itemText(x) for x in xrange(self.instruction_selector.count())]
        items = [x for x in self.instructions if x not in already_added]
        if len(items) == 0:
            print "Nothing else to add"
        else:
            sys, ok = QInputDialog.getItem(self, "Instruction selector", "Instruction stub to add:", items)
            if ok:
                self.instruction_selector.addItem(sys)

    def remove_instr_action(self):
        self.instruction_selector.removeItem(self.instruction_selector.currentIndex())

    def load_config_clicked(self):
        filename =  QFileDialog.getOpenFileName()[0]
        filepath = Path(filename)
        if not(filepath != "" and filepath.exists()):
            print "Invalid file given '%s'" % str(filepath)
            return

        raw = filepath.bytes()
        json_data = json.loads(raw)
        self.core.configuration.Clear()
        try:
            json2pb(self.core.configuration, json_data)
        except:
            print "Invalid JSON data given"
            return

        # -- Clear everything
        self.inputs_table.clearContents()
        self.inputs_table.setRowCount(0)
        self.initial_state_list.clear()
        self.bp_list.clear()
        self.start_field.clear()
        self.stop_field.clear()
        self.policy_table.clearContents()
        self.policy_table.setRowCount(0)
        self.libcall_selector.clear()
        self.syscall_selector.clear()
        self.instruction_selector.clear()
        # ------------
        # -- Fill everything back
        if json_data.has_key("start"):
            self.start_field.setText(hex(json_data["start"]))
        if json_data.has_key("stop"):
            self.stop_field.setText(hex(json_data["stop"]))
        if json_data.has_key("libcalls"):
            for lib in [x for x in json_data["libcalls"] if x["name"] in self.libcalls]:
                self.libcall_selector.addItem(lib["name"])
        if json_data.has_key("syscalls"):
            for lib in [x for x in json_data["syscalls"] if x["name"] in self.syscalls]:
                self.syscall_selector.addItem(lib["name"])
        if json_data.has_key("instrs"):
            for i in [x for x in json_data["instrs"] if x["ident"].lower() in self.instructions]:
                self.instruction_selector.addItem(i["ident"].lower())
        if json_data.has_key("policy"):
            for pol in json_data["policy"]:
                i = self.add_policy_item_action()
                split = pol.split(" => ")
                split2 = split[0].split("::")
                if len(split2) == 1:
                    self.set_policy_item_values(i, [split[0],"", "", "", split[1]])
                else:
                    self.set_policy_item_values(i, split2+[split[1]])
        if json_data.has_key("inputs"):
            for input in json_data["inputs"]:
                print "Get in input !"
                i = self.add_input_action()
                wid = self.inputs_table.cellWidget(i, 0)
                wid.setCurrentIndex(wid.findText(input["typeid"]))
                self.inputs_table.item(i, 1).setText(hex(input["address"]))
                wid = self.inputs_table.cellWidget(i, 4)
                wid.setCurrentIndex(wid.findText(input["action"]))
                wid = self.inputs_table.cellWidget(i, 5)
                wid.setCurrentIndex(wid.findText(input["when"]))
                if input["typeid"] == "REG":
                    self.inputs_table.item(i, 2).setText(input["reg"]["name"])
                    reg = input['reg']["value"]
                    value = {"BIT8":reg["value_8"], "BIT16":reg["value_16"], "BIT32":reg["value_32"],
                             "BIT64":reg["value_64"], "BIT80":reg["value_80"], "BIT128":reg["value_128"],
                             "BIT256":reg["value_256"]}[reg["typeid"]]
                    if isinstance(value, int):
                        self.inputs_table.item(i, 3).setText(hex(value))
                    else:
                        self.inputs_table.item(i, 3).setText(to_hex(value))
                else:
                    self.inputs_table.item(i, 2).setText(hex(input["mem"]["addr"]))
                    self.inputs_table.item(i, 3).setText(to_hex(base64.b64decode(input["mem"]["value"])))
        if json_data.has_key("breakpoins"):
            for bp in json_data["breakpoints"]:
                self.bp_list.addItem(hex(bp))
        if json_data.has_key('initial_state'):
            for item in json_data["initial_state"]:
                self.initial_state_list.addItem("%x -> %x: %s" %(item["addr"], item["addr"]+len(item["value"]), item["value"]))
        if json_data.has_key("direction"):
            self.direction_selector.setCurrentIndex(self.direction_selector.findText(json_data["direction"].title()))
        if json_data.has_key("callcvt"):
            self.callcvt_selector.setCurrentIndex(self.callcvt_selector.findText(json_data["callcvt"].lower()))
        if json_data.has_key("ksteps"):
            self.k_spinbox.setValue(json_data["ksteps"])
        if json_data.has_key("analysis_name"):
            self.analysis_name_selector.setCurrentIndex(self.analysis_name_selector.findText(json_data["analysis_name"]))
        if json_data.has_key("solver"):
            index = self.solver_selector.findText(json_data["solver"])
            if index != -1:
                self.solver_selector.setCurrentIndex(index)
        if json_data.has_key("incremental"):
            self.incremental_solving_checkbox.setChecked(json_data["incremental"])
        if json_data.has_key("timeout"):
            self.timeout_spinbox.setValue(json_data["timeout"])
        if json_data.has_key("optim_cstprop"):
            self.cstprop_checkbox.setChecked(json_data["optim_cstprop"])
        if json_data.has_key("optim_rebase"):
            self.rebase_checkbox.setChecked(json_data["optim_rebase"])
        if json_data.has_key("optim_row"):
            self.row_checkbox.setChecked(json_data["optim_row"])
        if json_data.has_key("default_action"):
            self.default_action_selector.setCurrentIndex(self.default_action_selector.findText(json_data["default_action"]))
        if json_data.has_key("verbosity"):
            self.verbosity_slider.setValue(json_data["verbosity"])

        if json_data.has_key("additional_parameters"):
            analyse = self.parent.analysis_from_name(json_data["additional_parameters"]["typeid"])
            analyse.config_widget.set_fields(json_data["additional_parameters"])

        self.configuration_textarea.setText(raw)
        # -------

    def set_policy_values(self, i, values):
        for col_id, value in enumerate(values):
            if col_id== len(values)-1:
                widget = self.policy_table.cellWidget(i, col_id)
                widget.setCurrentIndex(widget.findText("".join(value.split())))
            else:
                self.policy_table.item(i, col_id).setText(value)

    def save_config_clicked(self, infile=True):
        raw_config = self.configuration_textarea.toPlainText()
        if raw_config == "":
            print "Press Generate button first"
        else:
            try:
                json_data = json.loads(raw_config)
                self.core.configuration.Clear()
                json2pb(self.core.configuration, json_data)
                if infile:
                    json_data = pb2json(self.core.configuration)
                    filename =  QFileDialog.getSaveFileName()[0]
                    filepath = Path(filename)
                    if filepath != '':
                        bytes = json.dumps(json_data, indent=4)
                        filepath.write_bytes(bytes)
                    else:
                        print "Invalid file given %s" % str(filepath)
            except KeyError as e:
                print "invalid key:"+e.message


    def generate_config_clicked(self):
        self.core.configuration.Clear()

        #-- Add inputs
        for row in xrange(self.inputs_table.rowCount()):
            input = self.core.configuration.inputs.add()
            widg = [self.inputs_table.item(row, x) if x in [1,2,3] else self.inputs_table.cellWidget(row, x) for x in xrange(self.inputs_table.columnCount())]
            type, where, addr_name, value, action, when = widg[0].currentText(), widg[1].text(), widg[2].text(), widg[3].text(), widg[4].currentText(), widg[5].currentText()
            input.typeid, input.action, input.when = getattr(input_t, type), getattr(common_pb2, action), getattr(input_t, when)
            try:
                input.address = int(where, 16) if where.startswith("0x") else int(where)
                if input.typeid == input_t.REG:
                    sz = register_name_to_size(addr_name)
                    if sz == -1:
                        print "Invalid register name %s on row %d of inputs" % (addr_name, row)
                        self.core.configuration.inputs.remove(input)
                        pass
                    elif sz <= 64:
                        value = int(value, 16) if value.startswith("0x") else int(value)
                    elif sz > 64 and len(value) != sz:
                        print "Register %s except a value of the exact sime size %d!=%s" % (addr_name, len(value), sz)
                        pass
                    input.reg.name = addr_name
                    input.reg.value.typeid = getattr(common_pb2, "BIT"+str(sz))
                    setattr(input.reg.value, "value_"+str(sz), value)
                else: #MEM
                    addr_name = int(addr_name, 16) if addr_name.startswith("0x") else int(addr_name)
                    input.mem.addr = addr_name
                    input.mem.value = hex_to_bin(value)
            except ValueError:
                print "Invalid field in row %d of inputs" % row
                self.core.configuration.inputs.remove(input)
        #---------

        #-- Initial state
        for from_addr, to_addr in [[int(y.split(":")[0],16) for y in self.initial_state_list.item(x).text().split(" -> ")] for x in xrange(self.initial_state_list.count())]:
            mem = self.core.configuration.initial_state.add()
            mem.addr = from_addr
            bytes = idc.GetManyBytes(from_addr, to_addr-from_addr+1)
            if bytes is None:
                print "Cannot retrieve bytes from %x to %x for initial state" % (from_addr, to_addr)
            else:
                #mem.value = base64.b64encode(bytes)
                mem.value = bytes
        #----------------

        for bp in [self.bp_list.itemText(x) for x in xrange(self.bp_list.count())]:
            self.core.configuration.breakpoints.append(int(bp, 16))

        try:
            if self.start_field.text() != "":
                raw = self.start_field.text()
                self.core.configuration.start = int(raw, 16) if raw.startswith("0x") else int(raw)
            if self.stop_field.text() != "":
                raw = self.stop_field.text()
                self.core.configuration.stop = int(raw, 16) if raw.startswith("0x") else int(raw)
        except ValueError:
            print "start or stop value invalid. Values ignored.."
        self.core.configuration.analysis_name = self.analysis_name_selector.currentText().lower()
        self.core.configuration.direction = getattr(common_pb2, self.direction_selector.currentText().upper())
        if self.k_spinbox.isVisible():
            self.core.configuration.ksteps = self.k_spinbox.value()
        self.core.configuration.callcvt = getattr(common_pb2, self.callcvt_selector.currentText().upper())
        self.core.configuration.default_action = getattr(common_pb2, self.default_action_selector.currentText().upper())
        self.core.configuration.verbosity = self.verbosity_slider.value()

        if self.callmap_checkbox.isChecked():
            imports = self.core.seg_mapping[".idata"] if self.core.ftype == "PE" else self.core.seg_mapping['.plt']
            start, stop = self.core.seg_mapping[".text"]
            current = start
            while current <= stop:
                inst = current
                if idc.GetMnem(inst) in ["call", "jmp"]:
                    is_dynamic = idc.GetOpType(inst, 0) in [idc.o_mem, idc.o_reg]
                    value = idc.GetOperandValue(inst, 0)
                    name = idc.GetOpnd(inst, 0)
                    if value >= imports[0] and value <= imports[1]:
                        entry = self.core.configuration.call_map.add()
                        entry.address = inst
                        entry.name = name
                current = idc.NextHead(current, stop)

        # -- Policy generation --
        for row in xrange(self.policy_table.rowCount()):
            count = self.policy_table.columnCount()
            elts = [self.policy_table.cellWidget(row, x).currentText() if x == count-1 else self.policy_table.cellWidget(row, x).text() for x in xrange(count)]
            if elts[0] == "default":
                s = elts[0]+" => "+elts[4]
            else:
                s = elts[0] +" :: "+elts[1]+" :: "+elts[2]+" :: "+elts[3]+" => "+elts[4]
            self.core.configuration.policy.append(s)
        # -----------------------

        # -- Stub Libcall/Syscall/Instruction
        for lib_name in [self.libcall_selector.itemText(x) for x in xrange(self.libcall_selector.count())]:
            libcall = self.core.configuration.libcalls.add()
            libcall.name = lib_name
            libcall.action = common_pb2.SKIP
            libcall.ident = getattr(libcall_pb2, lib_name.upper())
            self.recurse_assign(getattr(libcall, lib_name.lower()))
        for sys_name in [self.syscall_selector.itemText(x) for x in xrange(self.syscall_selector.count())]:
            syscall = self.core.configuration.syscalls.add()
            #TODO: Set the ID + IDENT
            syscall.name = sys_name
            syscall.action = common_pb2.SKIP
            syscall.ident = getattr(syscall_pb2, sys_name.upper())
            self.recurse_assign(syscall)
        for ins in [self.instruction_selector.itemText(x) for x in xrange(self.instruction_selector.count())]:
            instruction = self.core.configuration.instrs.add()
            instruction.ident = getattr(instruction_pb2, ins.upper())
            self.recurse_assign(instruction)
        # ---------------

        # -- Solver & Optims
        solver = self.solver_selector.currentText()
        if solver != "auto":
            self.core.configuration.solver = getattr(common_pb2, solver.upper())
        if self.incremental_solving_checkbox.isChecked():
            self.core.configuration.incremental = True
        self.core.configuration.timeout = self.timeout_spinbox.value()
        self.core.configuration.optim_cstprop = self.cstprop_checkbox.isChecked()
        self.core.configuration.optim_rebase = self.rebase_checkbox.isChecked()
        self.core.configuration.optim_row = self.row_checkbox.isChecked()
        #-------------------

        # -- Analysis specific parameters
        if self.analysis_name_selector.currentIndex() != -1:
            name = self.analysis_name_selector.currentText()
            analysis = self.parent.analysis_from_name(name)
            param = analysis.config_widget.serialize()
            if param is None:
                return False
            else:
                self.core.configuration.additional_parameters.CopyFrom(param)
        # --------------------------------


        #-- Now generate !
        json_conf = pb2json(self.core.configuration)
        generated = json.dumps(json_conf, indent=4)
        self.configuration_textarea.setPlainText(generated)
        return True


    def recurse_assign(self, pb):
        for field in pb.DESCRIPTOR.fields:
            if field.type == field.TYPE_MESSAGE:
                self.recurse_assign(getattr(pb, field.name, None))
            elif field.type == field.TYPE_ENUM and field.enum_type.name == "action":
                value = field.default_value if field.has_default_value else field.enum_type.values_by_name["DEFAULT"].number
                setattr(pb, field.name, value)


    def trigger_analysis_clicked(self):
        print "Trigger analysis clicked !"
        if self.configuration_textarea.toPlainText() == "":
            if not self.generate_config_clicked():
                print "Configuration generation failed !"
                return

        self.save_config_clicked(infile=False)

        name = self.core.configuration.analysis_name.upper()               
        analysis_kind = self.parent.analysis_from_name(name).kind

        if self.stream_radiobutton.isChecked():
            self.parent.start_analysis(name, self.core.configuration, is_stream=True)
        else:
            if analysis_kind in [STATIC, STATIC_AND_DYNAMIC]:
                self.parent.start_analysis(name, self.core.configuration)
            else:
                if self.trace_selector.currentIndex() == -1:
                    print "no trace selected nor loaded"
                else:
                    id = int(self.trace_selector.currentText().split(" ")[0][1:]) # TODO: find another to get trace id
                    trace = self.core.traces[id]
                    self.parent.start_analysis(name, self.core.configuration, trace=trace)

#------------------------------------------------------------------------
#------------------------------ Generated -------------------------------
#------------------------------------------------------------------------

    def setupUi(self, Analysis):
        def _fromUtf8(s):
            return s
        def _translate(x,y,z):
            return y
        Analysis.setObjectName(_fromUtf8("Analysis"))
        Analysis.resize(758, 530)
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(Analysis)
        self.verticalLayout_3.setObjectName(_fromUtf8("verticalLayout_3"))
        self.splitter = QtWidgets.QSplitter(Analysis)
        self.splitter.setOrientation(QtCore.Qt.Horizontal)
        self.splitter.setObjectName(_fromUtf8("splitter"))
        self.verticalLayoutWidget = QtWidgets.QWidget(self.splitter)
        self.verticalLayoutWidget.setObjectName(_fromUtf8("verticalLayoutWidget"))
        self.left_layout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.left_layout.setSizeConstraint(QtWidgets.QLayout.SetDefaultConstraint)
        self.left_layout.setObjectName(_fromUtf8("left_layout"))
        self.configuration_label = QtWidgets.QLabel(self.verticalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.configuration_label.sizePolicy().hasHeightForWidth())
        self.configuration_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.configuration_label.setFont(font)
        self.configuration_label.setAlignment(QtCore.Qt.AlignCenter)
        self.configuration_label.setObjectName(_fromUtf8("configuration_label"))
        self.left_layout.addWidget(self.configuration_label)
        self.widget = QtWidgets.QWidget(self.verticalLayoutWidget)
        self.widget.setObjectName(_fromUtf8("widget"))
        self.verticalLayout_12 = QtWidgets.QVBoxLayout(self.widget)
        self.verticalLayout_12.setObjectName(_fromUtf8("verticalLayout_12"))
        self.splitter_2 = QtWidgets.QSplitter(self.widget)
        self.splitter_2.setOrientation(QtCore.Qt.Vertical)
        self.splitter_2.setObjectName(_fromUtf8("splitter_2"))
        self.verticalLayoutWidget_4 = QtWidgets.QWidget(self.splitter_2)
        self.verticalLayoutWidget_4.setObjectName(_fromUtf8("verticalLayoutWidget_4"))
        self.verticalLayout_7 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_4)
        self.verticalLayout_7.setObjectName(_fromUtf8("verticalLayout_7"))
        self.configuration_textarea = QtWidgets.QTextEdit(self.verticalLayoutWidget_4)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.configuration_textarea.sizePolicy().hasHeightForWidth())
        self.configuration_textarea.setSizePolicy(sizePolicy)
        self.configuration_textarea.setMinimumSize(QtCore.QSize(0, 0))
        self.configuration_textarea.setObjectName(_fromUtf8("configuration_textarea"))
        self.verticalLayout_7.addWidget(self.configuration_textarea)
        self.verticalLayoutWidget_5 = QtWidgets.QWidget(self.splitter_2)
        self.verticalLayoutWidget_5.setObjectName(_fromUtf8("verticalLayoutWidget_5"))
        self.verticalLayout_11 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_5)
        self.verticalLayout_11.setObjectName(_fromUtf8("verticalLayout_11"))
        self.common_group = QtWidgets.QGroupBox(self.verticalLayoutWidget_5)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Maximum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.common_group.sizePolicy().hasHeightForWidth())
        self.common_group.setSizePolicy(sizePolicy)
        self.common_group.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.common_group.setSizeIncrement(QtCore.QSize(0, 0))
        self.common_group.setBaseSize(QtCore.QSize(0, 0))
        self.common_group.setObjectName(_fromUtf8("common_group"))
        self.verticalLayout_13 = QtWidgets.QVBoxLayout(self.common_group)
        self.verticalLayout_13.setObjectName(_fromUtf8("verticalLayout_13"))
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName(_fromUtf8("horizontalLayout_4"))
        self.input_label = QtWidgets.QLabel(self.common_group)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.input_label.sizePolicy().hasHeightForWidth())
        self.input_label.setSizePolicy(sizePolicy)
        self.input_label.setObjectName(_fromUtf8("input_label"))
        self.horizontalLayout_4.addWidget(self.input_label)
        self.inputs_table = QtWidgets.QTableWidget(self.common_group)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.inputs_table.sizePolicy().hasHeightForWidth())
        self.inputs_table.setSizePolicy(sizePolicy)
        self.inputs_table.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.inputs_table.setObjectName(_fromUtf8("inputs_table"))
        self.inputs_table.setColumnCount(0)
        self.inputs_table.setRowCount(0)
        self.horizontalLayout_4.addWidget(self.inputs_table)
        self.add_input_button = QtWidgets.QPushButton(self.common_group)
        self.add_input_button.setMaximumSize(QtCore.QSize(30, 30))
        self.add_input_button.setText(_fromUtf8(""))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/icons/icons/open-iconic-master/png/3x/plus-3x.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.add_input_button.setIcon(icon)
        self.add_input_button.setIconSize(QtCore.QSize(14, 14))
        self.add_input_button.setObjectName(_fromUtf8("add_input_button"))
        self.horizontalLayout_4.addWidget(self.add_input_button)
        self.verticalLayout_13.addLayout(self.horizontalLayout_4)
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setObjectName(_fromUtf8("horizontalLayout_5"))
        self.initial_state_label = QtWidgets.QLabel(self.common_group)
        self.initial_state_label.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.initial_state_label.setObjectName(_fromUtf8("initial_state_label"))
        self.horizontalLayout_5.addWidget(self.initial_state_label)
        self.initial_state_from = QtWidgets.QLabel(self.common_group)
        self.initial_state_from.setObjectName(_fromUtf8("initial_state_from"))
        self.horizontalLayout_5.addWidget(self.initial_state_from)
        self.initial_state_from_field = QtWidgets.QLineEdit(self.common_group)
        self.initial_state_from_field.setMaximumSize(QtCore.QSize(100, 16777215))
        self.initial_state_from_field.setToolTip(_fromUtf8(""))
        self.initial_state_from_field.setWhatsThis(_fromUtf8(""))
        self.initial_state_from_field.setAlignment(QtCore.Qt.AlignCenter)
        self.initial_state_from_field.setPlaceholderText(_fromUtf8(""))
        self.initial_state_from_field.setObjectName(_fromUtf8("initial_state_from_field"))
        self.horizontalLayout_5.addWidget(self.initial_state_from_field)
        self.initial_state_to_label = QtWidgets.QLabel(self.common_group)
        self.initial_state_to_label.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.initial_state_to_label.setObjectName(_fromUtf8("initial_state_to_label"))
        self.horizontalLayout_5.addWidget(self.initial_state_to_label)
        self.initial_state_to_field = QtWidgets.QLineEdit(self.common_group)
        self.initial_state_to_field.setMaximumSize(QtCore.QSize(100, 16777215))
        self.initial_state_to_field.setObjectName(_fromUtf8("initial_state_to_field"))
        self.horizontalLayout_5.addWidget(self.initial_state_to_field)
        self.add_initial_state_button = QtWidgets.QPushButton(self.common_group)
        self.add_initial_state_button.setMaximumSize(QtCore.QSize(25, 25))
        self.add_initial_state_button.setText(_fromUtf8(""))
        self.add_initial_state_button.setIcon(icon)
        self.add_initial_state_button.setIconSize(QtCore.QSize(12, 12))
        self.add_initial_state_button.setObjectName(_fromUtf8("add_initial_state_button"))
        self.horizontalLayout_5.addWidget(self.add_initial_state_button)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_5.addItem(spacerItem)
        self.verticalLayout_13.addLayout(self.horizontalLayout_5)
        self.initial_state_list = QtWidgets.QListWidget(self.common_group)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.initial_state_list.sizePolicy().hasHeightForWidth())
        self.initial_state_list.setSizePolicy(sizePolicy)
        self.initial_state_list.setMinimumSize(QtCore.QSize(0, 20))
        self.initial_state_list.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.initial_state_list.setObjectName(_fromUtf8("initial_state_list"))
        self.verticalLayout_13.addWidget(self.initial_state_list)
        self.verticalLayout_11.addWidget(self.common_group)
        self.verticalLayout_12.addWidget(self.splitter_2)
        self.left_layout.addWidget(self.widget)
        self.verticalLayoutWidget_2 = QtWidgets.QWidget(self.splitter)
        self.verticalLayoutWidget_2.setObjectName(_fromUtf8("verticalLayoutWidget_2"))
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_2)
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.scrollArea = QtWidgets.QScrollArea(self.verticalLayoutWidget_2)
        self.scrollArea.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setObjectName(_fromUtf8("scrollArea"))
        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, -25, 338, 1039))
        self.scrollAreaWidgetContents.setObjectName(_fromUtf8("scrollAreaWidgetContents"))
        self.verticalLayout = QtWidgets.QVBoxLayout(self.scrollAreaWidgetContents)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.pinsec_group = QtWidgets.QGroupBox(self.scrollAreaWidgetContents)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.pinsec_group.sizePolicy().hasHeightForWidth())
        self.pinsec_group.setSizePolicy(sizePolicy)
        self.pinsec_group.setObjectName(_fromUtf8("pinsec_group"))
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.pinsec_group)
        self.verticalLayout_4.setObjectName(_fromUtf8("verticalLayout_4"))
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.bp_label = QtWidgets.QLabel(self.pinsec_group)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.bp_label.sizePolicy().hasHeightForWidth())
        self.bp_label.setSizePolicy(sizePolicy)
        self.bp_label.setObjectName(_fromUtf8("bp_label"))
        self.horizontalLayout.addWidget(self.bp_label)
        self.bp_list = QtWidgets.QComboBox(self.pinsec_group)
        self.bp_list.setObjectName(_fromUtf8("bp_list"))
        self.horizontalLayout.addWidget(self.bp_list)
        self.add_bp_button = QtWidgets.QPushButton(self.pinsec_group)
        self.add_bp_button.setMaximumSize(QtCore.QSize(25, 25))
        self.add_bp_button.setText(_fromUtf8(""))
        self.add_bp_button.setIcon(icon)
        self.add_bp_button.setIconSize(QtCore.QSize(12, 12))
        self.add_bp_button.setObjectName(_fromUtf8("add_bp_button"))
        self.horizontalLayout.addWidget(self.add_bp_button)
        self.remove_bp_button = QtWidgets.QPushButton(self.pinsec_group)
        self.remove_bp_button.setMaximumSize(QtCore.QSize(25, 25))
        self.remove_bp_button.setText(_fromUtf8(""))
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(_fromUtf8(":/icons/icons/open-iconic-master/png/3x/minus-3x.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.remove_bp_button.setIcon(icon1)
        self.remove_bp_button.setIconSize(QtCore.QSize(12, 12))
        self.remove_bp_button.setObjectName(_fromUtf8("remove_bp_button"))
        self.horizontalLayout.addWidget(self.remove_bp_button)
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem1)
        self.verticalLayout_4.addLayout(self.horizontalLayout)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
        self.start_label = QtWidgets.QLabel(self.pinsec_group)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.start_label.sizePolicy().hasHeightForWidth())
        self.start_label.setSizePolicy(sizePolicy)
        self.start_label.setObjectName(_fromUtf8("start_label"))
        self.horizontalLayout_3.addWidget(self.start_label)
        self.start_field = QtWidgets.QLineEdit(self.pinsec_group)
        self.start_field.setMaximumSize(QtCore.QSize(100, 16777215))
        self.start_field.setObjectName(_fromUtf8("start_field"))
        self.horizontalLayout_3.addWidget(self.start_field)
        self.detect_start_button = QtWidgets.QPushButton(self.pinsec_group)
        self.detect_start_button.setMaximumSize(QtCore.QSize(25, 25))
        self.detect_start_button.setText(_fromUtf8(""))
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(_fromUtf8(":/icons/icons/open-iconic-master/png/3x/target-3x.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.detect_start_button.setIcon(icon2)
        self.detect_start_button.setIconSize(QtCore.QSize(12, 12))
        self.detect_start_button.setObjectName(_fromUtf8("detect_start_button"))
        self.horizontalLayout_3.addWidget(self.detect_start_button)
        self.stop_label = QtWidgets.QLabel(self.pinsec_group)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.stop_label.sizePolicy().hasHeightForWidth())
        self.stop_label.setSizePolicy(sizePolicy)
        self.stop_label.setObjectName(_fromUtf8("stop_label"))
        self.horizontalLayout_3.addWidget(self.stop_label)
        self.stop_field = QtWidgets.QLineEdit(self.pinsec_group)
        self.stop_field.setMaximumSize(QtCore.QSize(100, 16777215))
        self.stop_field.setObjectName(_fromUtf8("stop_field"))
        self.horizontalLayout_3.addWidget(self.stop_field)
        self.detect_stop_button = QtWidgets.QPushButton(self.pinsec_group)
        self.detect_stop_button.setMaximumSize(QtCore.QSize(25, 25))
        self.detect_stop_button.setText(_fromUtf8(""))
        self.detect_stop_button.setIcon(icon2)
        self.detect_stop_button.setIconSize(QtCore.QSize(12, 12))
        self.detect_stop_button.setObjectName(_fromUtf8("detect_stop_button"))
        self.horizontalLayout_3.addWidget(self.detect_stop_button)
        spacerItem2 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem2)
        self.verticalLayout_4.addLayout(self.horizontalLayout_3)
        self.start_entrypoint_checkbox = QtWidgets.QCheckBox(self.pinsec_group)
        self.start_entrypoint_checkbox.setObjectName(_fromUtf8("start_entrypoint_checkbox"))
        self.verticalLayout_4.addWidget(self.start_entrypoint_checkbox)
        self.trace_waves_checkbox = QtWidgets.QCheckBox(self.pinsec_group)
        self.trace_waves_checkbox.setObjectName(_fromUtf8("trace_waves_checkbox"))
        self.verticalLayout_4.addWidget(self.trace_waves_checkbox)
        self.antidebug_checkbox = QtWidgets.QCheckBox(self.pinsec_group)
        self.antidebug_checkbox.setObjectName(_fromUtf8("antidebug_checkbox"))
        self.verticalLayout_4.addWidget(self.antidebug_checkbox)
        self.verticalLayout.addWidget(self.pinsec_group)
        self.analysis_group = QtWidgets.QGroupBox(self.scrollAreaWidgetContents)
        self.analysis_group.setObjectName(_fromUtf8("analysis_group"))
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.analysis_group)
        self.verticalLayout_5.setObjectName(_fromUtf8("verticalLayout_5"))
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_7.setObjectName(_fromUtf8("horizontalLayout_7"))
        self.analysis_name_label = QtWidgets.QLabel(self.analysis_group)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.analysis_name_label.sizePolicy().hasHeightForWidth())
        self.analysis_name_label.setSizePolicy(sizePolicy)
        self.analysis_name_label.setMinimumSize(QtCore.QSize(65, 0))
        self.analysis_name_label.setObjectName(_fromUtf8("analysis_name_label"))
        self.horizontalLayout_7.addWidget(self.analysis_name_label)
        self.analysis_name_selector = QtWidgets.QComboBox(self.analysis_group)
        self.analysis_name_selector.setMinimumSize(QtCore.QSize(150, 0))
        self.analysis_name_selector.setObjectName(_fromUtf8("analysis_name_selector"))
        self.horizontalLayout_7.addWidget(self.analysis_name_selector)
        spacerItem3 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_7.addItem(spacerItem3)
        self.verticalLayout_5.addLayout(self.horizontalLayout_7)
        self.horizontalLayout_8 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_8.setObjectName(_fromUtf8("horizontalLayout_8"))
        self.direction_label = QtWidgets.QLabel(self.analysis_group)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.direction_label.sizePolicy().hasHeightForWidth())
        self.direction_label.setSizePolicy(sizePolicy)
        self.direction_label.setMinimumSize(QtCore.QSize(65, 0))
        self.direction_label.setObjectName(_fromUtf8("direction_label"))
        self.horizontalLayout_8.addWidget(self.direction_label)
        self.direction_selector = QtWidgets.QComboBox(self.analysis_group)
        self.direction_selector.setMinimumSize(QtCore.QSize(150, 0))
        self.direction_selector.setObjectName(_fromUtf8("direction_selector"))
        self.horizontalLayout_8.addWidget(self.direction_selector)
        self.k_label = QtWidgets.QLabel(self.analysis_group)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.k_label.sizePolicy().hasHeightForWidth())
        self.k_label.setSizePolicy(sizePolicy)
        self.k_label.setObjectName(_fromUtf8("k_label"))
        self.horizontalLayout_8.addWidget(self.k_label)
        self.k_spinbox = QtWidgets.QSpinBox(self.analysis_group)
        self.k_spinbox.setMaximumSize(QtCore.QSize(50, 16777215))
        self.k_spinbox.setMaximum(1000000000)
        self.k_spinbox.setProperty("value", 0)
        self.k_spinbox.setObjectName(_fromUtf8("k_spinbox"))
        self.horizontalLayout_8.addWidget(self.k_spinbox)
        spacerItem4 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_8.addItem(spacerItem4)
        self.verticalLayout_5.addLayout(self.horizontalLayout_8)
        self.horizontalLayout_10 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_10.setObjectName(_fromUtf8("horizontalLayout_10"))
        self.callcvt_label = QtWidgets.QLabel(self.analysis_group)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.callcvt_label.sizePolicy().hasHeightForWidth())
        self.callcvt_label.setSizePolicy(sizePolicy)
        self.callcvt_label.setMinimumSize(QtCore.QSize(65, 0))
        self.callcvt_label.setObjectName(_fromUtf8("callcvt_label"))
        self.horizontalLayout_10.addWidget(self.callcvt_label)
        self.callcvt_selector = QtWidgets.QComboBox(self.analysis_group)
        self.callcvt_selector.setMinimumSize(QtCore.QSize(150, 0))
        self.callcvt_selector.setObjectName(_fromUtf8("callcvt_selector"))
        self.horizontalLayout_10.addWidget(self.callcvt_selector)
        spacerItem5 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_10.addItem(spacerItem5)
        self.verticalLayout_5.addLayout(self.horizontalLayout_10)
        self.horizontalLayout_11 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_11.setObjectName(_fromUtf8("horizontalLayout_11"))
        self.trace_input_label = QtWidgets.QLabel(self.analysis_group)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.trace_input_label.sizePolicy().hasHeightForWidth())
        self.trace_input_label.setSizePolicy(sizePolicy)
        self.trace_input_label.setMinimumSize(QtCore.QSize(65, 0))
        self.trace_input_label.setObjectName(_fromUtf8("trace_input_label"))
        self.horizontalLayout_11.addWidget(self.trace_input_label)
        self.verticalLayout_10 = QtWidgets.QVBoxLayout()
        self.verticalLayout_10.setObjectName(_fromUtf8("verticalLayout_10"))
        self.remote_radiobutton = QtWidgets.QRadioButton(self.analysis_group)
        self.remote_radiobutton.setObjectName(_fromUtf8("remote_radiobutton"))
        self.verticalLayout_10.addWidget(self.remote_radiobutton)
        self.local_radiobutton = QtWidgets.QRadioButton(self.analysis_group)
        self.local_radiobutton.setObjectName(_fromUtf8("local_radiobutton"))
        self.verticalLayout_10.addWidget(self.local_radiobutton)
        self.stream_radiobutton = QtWidgets.QRadioButton(self.analysis_group)
        self.stream_radiobutton.setObjectName(_fromUtf8("stream_radiobutton"))
        self.verticalLayout_10.addWidget(self.stream_radiobutton)
        self.horizontalLayout_11.addLayout(self.verticalLayout_10)
        self.verticalLayout_5.addLayout(self.horizontalLayout_11)
        self.horizontalLayout_12 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_12.setObjectName(_fromUtf8("horizontalLayout_12"))
        self.trace_label = QtWidgets.QLabel(self.analysis_group)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.trace_label.sizePolicy().hasHeightForWidth())
        self.trace_label.setSizePolicy(sizePolicy)
        self.trace_label.setMinimumSize(QtCore.QSize(65, 0))
        self.trace_label.setObjectName(_fromUtf8("trace_label"))
        self.horizontalLayout_12.addWidget(self.trace_label)
        self.trace_selector = QtWidgets.QComboBox(self.analysis_group)
        self.trace_selector.setMinimumSize(QtCore.QSize(150, 0))
        self.trace_selector.setObjectName(_fromUtf8("trace_selector"))
        self.horizontalLayout_12.addWidget(self.trace_selector)
        spacerItem6 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_12.addItem(spacerItem6)
        self.verticalLayout_5.addLayout(self.horizontalLayout_12)
        self.callmap_checkbox = QtWidgets.QCheckBox(self.analysis_group)
        self.callmap_checkbox.setObjectName(_fromUtf8("callmap_checkbox"))
        self.verticalLayout_5.addWidget(self.callmap_checkbox)
        self.horizontalLayout_18 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_18.setObjectName(_fromUtf8("horizontalLayout_18"))
        self.verbosity_label = QtWidgets.QLabel(self.analysis_group)
        self.verbosity_label.setObjectName(_fromUtf8("verbosity_label"))
        self.horizontalLayout_18.addWidget(self.verbosity_label)
        self.verbosity_slider = QtWidgets.QSlider(self.analysis_group)
        self.verbosity_slider.setMaximum(5)
        self.verbosity_slider.setOrientation(QtCore.Qt.Horizontal)
        self.verbosity_slider.setInvertedAppearance(False)
        self.verbosity_slider.setTickPosition(QtWidgets.QSlider.TicksBelow)
        self.verbosity_slider.setTickInterval(1)
        self.verbosity_slider.setObjectName(_fromUtf8("verbosity_slider"))
        self.horizontalLayout_18.addWidget(self.verbosity_slider)
        self.verticalLayout_5.addLayout(self.horizontalLayout_18)
        self.analysis_specific_group = QtWidgets.QGroupBox(self.analysis_group)
        self.analysis_specific_group.setObjectName(_fromUtf8("analysis_specific_group"))
        self.analysis_specific_layout = QtWidgets.QVBoxLayout(self.analysis_specific_group)
        self.analysis_specific_layout.setObjectName(_fromUtf8("analysis_specific_layout"))
        self.verticalLayout_5.addWidget(self.analysis_specific_group)
        self.cocnsymb_group = QtWidgets.QGroupBox(self.analysis_group)
        self.cocnsymb_group.setObjectName(_fromUtf8("cocnsymb_group"))
        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.cocnsymb_group)
        self.verticalLayout_6.setObjectName(_fromUtf8("verticalLayout_6"))
        self.policy_layout = QtWidgets.QHBoxLayout()
        self.policy_layout.setObjectName(_fromUtf8("policy_layout"))
        self.policy_label = QtWidgets.QLabel(self.cocnsymb_group)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.policy_label.sizePolicy().hasHeightForWidth())
        self.policy_label.setSizePolicy(sizePolicy)
        self.policy_label.setObjectName(_fromUtf8("policy_label"))
        self.policy_layout.addWidget(self.policy_label)
        self.policy_selector = QtWidgets.QComboBox(self.cocnsymb_group)
        self.policy_selector.setMinimumSize(QtCore.QSize(100, 0))
        self.policy_selector.setMaximumSize(QtCore.QSize(16777215, 25))
        self.policy_selector.setObjectName(_fromUtf8("policy_selector"))
        self.policy_layout.addWidget(self.policy_selector)
        self.add_policy_item_button = QtWidgets.QPushButton(self.cocnsymb_group)
        self.add_policy_item_button.setMinimumSize(QtCore.QSize(25, 25))
        self.add_policy_item_button.setMaximumSize(QtCore.QSize(25, 25))
        self.add_policy_item_button.setText(_fromUtf8(""))
        self.add_policy_item_button.setIcon(icon)
        self.add_policy_item_button.setIconSize(QtCore.QSize(12, 12))
        self.add_policy_item_button.setObjectName(_fromUtf8("add_policy_item_button"))
        self.policy_layout.addWidget(self.add_policy_item_button)
        self.remove_policy_item_button = QtWidgets.QPushButton(self.cocnsymb_group)
        self.remove_policy_item_button.setMinimumSize(QtCore.QSize(25, 25))
        self.remove_policy_item_button.setMaximumSize(QtCore.QSize(25, 25))
        self.remove_policy_item_button.setText(_fromUtf8(""))
        self.remove_policy_item_button.setIcon(icon1)
        self.remove_policy_item_button.setIconSize(QtCore.QSize(12, 12))
        self.remove_policy_item_button.setObjectName(_fromUtf8("remove_policy_item_button"))
        self.policy_layout.addWidget(self.remove_policy_item_button)
        self.help_policy_button = QtWidgets.QPushButton(self.cocnsymb_group)
        self.help_policy_button.setMinimumSize(QtCore.QSize(25, 25))
        self.help_policy_button.setMaximumSize(QtCore.QSize(25, 25))
        self.help_policy_button.setText(_fromUtf8(""))
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap(_fromUtf8(":/icons/icons/open-iconic-master/png/3x/question-mark-3x.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.help_policy_button.setIcon(icon3)
        self.help_policy_button.setIconSize(QtCore.QSize(12, 12))
        self.help_policy_button.setObjectName(_fromUtf8("help_policy_button"))
        self.policy_layout.addWidget(self.help_policy_button)
        spacerItem7 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.policy_layout.addItem(spacerItem7)
        self.verticalLayout_6.addLayout(self.policy_layout)
        self.policy_table = QtWidgets.QTableWidget(self.cocnsymb_group)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.policy_table.sizePolicy().hasHeightForWidth())
        self.policy_table.setSizePolicy(sizePolicy)
        self.policy_table.setMinimumSize(QtCore.QSize(0, 0))
        self.policy_table.setMaximumSize(QtCore.QSize(16777215, 100))
        self.policy_table.setBaseSize(QtCore.QSize(0, 0))
        self.policy_table.setObjectName(_fromUtf8("policy_table"))
        self.policy_table.setColumnCount(0)
        self.policy_table.setRowCount(0)
        self.verticalLayout_6.addWidget(self.policy_table)
        self.horizontalLayout_13 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_13.setObjectName(_fromUtf8("horizontalLayout_13"))
        self.libcall_label = QtWidgets.QLabel(self.cocnsymb_group)
        self.libcall_label.setMinimumSize(QtCore.QSize(100, 0))
        self.libcall_label.setObjectName(_fromUtf8("libcall_label"))
        self.horizontalLayout_13.addWidget(self.libcall_label)
        self.libcall_selector = QtWidgets.QComboBox(self.cocnsymb_group)
        self.libcall_selector.setMinimumSize(QtCore.QSize(100, 0))
        self.libcall_selector.setObjectName(_fromUtf8("libcall_selector"))
        self.horizontalLayout_13.addWidget(self.libcall_selector)
        self.add_libcall_button = QtWidgets.QPushButton(self.cocnsymb_group)
        self.add_libcall_button.setMinimumSize(QtCore.QSize(25, 25))
        self.add_libcall_button.setMaximumSize(QtCore.QSize(25, 25))
        self.add_libcall_button.setText(_fromUtf8(""))
        self.add_libcall_button.setIcon(icon)
        self.add_libcall_button.setIconSize(QtCore.QSize(12, 12))
        self.add_libcall_button.setObjectName(_fromUtf8("add_libcall_button"))
        self.horizontalLayout_13.addWidget(self.add_libcall_button)
        self.remove_libcall_button = QtWidgets.QPushButton(self.cocnsymb_group)
        self.remove_libcall_button.setMinimumSize(QtCore.QSize(25, 25))
        self.remove_libcall_button.setMaximumSize(QtCore.QSize(25, 25))
        self.remove_libcall_button.setText(_fromUtf8(""))
        self.remove_libcall_button.setIcon(icon1)
        self.remove_libcall_button.setIconSize(QtCore.QSize(12, 12))
        self.remove_libcall_button.setObjectName(_fromUtf8("remove_libcall_button"))
        self.horizontalLayout_13.addWidget(self.remove_libcall_button)
        spacerItem8 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_13.addItem(spacerItem8)
        self.verticalLayout_6.addLayout(self.horizontalLayout_13)
        self.horizontalLayout_14 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_14.setObjectName(_fromUtf8("horizontalLayout_14"))
        self.syscall_label = QtWidgets.QLabel(self.cocnsymb_group)
        self.syscall_label.setMinimumSize(QtCore.QSize(100, 0))
        self.syscall_label.setObjectName(_fromUtf8("syscall_label"))
        self.horizontalLayout_14.addWidget(self.syscall_label)
        self.syscall_selector = QtWidgets.QComboBox(self.cocnsymb_group)
        self.syscall_selector.setMinimumSize(QtCore.QSize(100, 0))
        self.syscall_selector.setObjectName(_fromUtf8("syscall_selector"))
        self.horizontalLayout_14.addWidget(self.syscall_selector)
        self.add_syscall_button = QtWidgets.QPushButton(self.cocnsymb_group)
        self.add_syscall_button.setMinimumSize(QtCore.QSize(25, 25))
        self.add_syscall_button.setMaximumSize(QtCore.QSize(25, 25))
        self.add_syscall_button.setText(_fromUtf8(""))
        self.add_syscall_button.setIcon(icon)
        self.add_syscall_button.setIconSize(QtCore.QSize(12, 12))
        self.add_syscall_button.setObjectName(_fromUtf8("add_syscall_button"))
        self.horizontalLayout_14.addWidget(self.add_syscall_button)
        self.remove_syscall_button = QtWidgets.QPushButton(self.cocnsymb_group)
        self.remove_syscall_button.setMinimumSize(QtCore.QSize(25, 25))
        self.remove_syscall_button.setMaximumSize(QtCore.QSize(25, 25))
        self.remove_syscall_button.setText(_fromUtf8(""))
        self.remove_syscall_button.setIcon(icon1)
        self.remove_syscall_button.setIconSize(QtCore.QSize(12, 12))
        self.remove_syscall_button.setObjectName(_fromUtf8("remove_syscall_button"))
        self.horizontalLayout_14.addWidget(self.remove_syscall_button)
        spacerItem9 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_14.addItem(spacerItem9)
        self.verticalLayout_6.addLayout(self.horizontalLayout_14)
        self.horizontalLayout_16 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_16.setObjectName(_fromUtf8("horizontalLayout_16"))
        self.instruction_label = QtWidgets.QLabel(self.cocnsymb_group)
        self.instruction_label.setMinimumSize(QtCore.QSize(100, 0))
        self.instruction_label.setObjectName(_fromUtf8("instruction_label"))
        self.horizontalLayout_16.addWidget(self.instruction_label)
        self.instruction_selector = QtWidgets.QComboBox(self.cocnsymb_group)
        self.instruction_selector.setMinimumSize(QtCore.QSize(100, 0))
        self.instruction_selector.setObjectName(_fromUtf8("instruction_selector"))
        self.horizontalLayout_16.addWidget(self.instruction_selector)
        self.add_instruction_button = QtWidgets.QPushButton(self.cocnsymb_group)
        self.add_instruction_button.setMinimumSize(QtCore.QSize(25, 25))
        self.add_instruction_button.setMaximumSize(QtCore.QSize(25, 25))
        self.add_instruction_button.setText(_fromUtf8(""))
        self.add_instruction_button.setIcon(icon)
        self.add_instruction_button.setIconSize(QtCore.QSize(12, 12))
        self.add_instruction_button.setObjectName(_fromUtf8("add_instruction_button"))
        self.horizontalLayout_16.addWidget(self.add_instruction_button)
        self.remove_instruction_button = QtWidgets.QPushButton(self.cocnsymb_group)
        self.remove_instruction_button.setMinimumSize(QtCore.QSize(25, 25))
        self.remove_instruction_button.setMaximumSize(QtCore.QSize(25, 25))
        self.remove_instruction_button.setText(_fromUtf8(""))
        self.remove_instruction_button.setIcon(icon1)
        self.remove_instruction_button.setIconSize(QtCore.QSize(12, 12))
        self.remove_instruction_button.setObjectName(_fromUtf8("remove_instruction_button"))
        self.horizontalLayout_16.addWidget(self.remove_instruction_button)
        spacerItem10 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_16.addItem(spacerItem10)
        self.verticalLayout_6.addLayout(self.horizontalLayout_16)
        self.horizontalLayout_15 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_15.setObjectName(_fromUtf8("horizontalLayout_15"))
        self.default_action_label = QtWidgets.QLabel(self.cocnsymb_group)
        self.default_action_label.setMinimumSize(QtCore.QSize(100, 0))
        self.default_action_label.setObjectName(_fromUtf8("default_action_label"))
        self.horizontalLayout_15.addWidget(self.default_action_label)
        self.default_action_selector = QtWidgets.QComboBox(self.cocnsymb_group)
        self.default_action_selector.setObjectName(_fromUtf8("default_action_selector"))
        self.horizontalLayout_15.addWidget(self.default_action_selector)
        spacerItem11 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_15.addItem(spacerItem11)
        self.verticalLayout_6.addLayout(self.horizontalLayout_15)
        self.verticalLayout_5.addWidget(self.cocnsymb_group)
        self.solving_group = QtWidgets.QGroupBox(self.analysis_group)
        self.solving_group.setObjectName(_fromUtf8("solving_group"))
        self.verticalLayout_8 = QtWidgets.QVBoxLayout(self.solving_group)
        self.verticalLayout_8.setObjectName(_fromUtf8("verticalLayout_8"))
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setObjectName(_fromUtf8("horizontalLayout_6"))
        self.solver_label = QtWidgets.QLabel(self.solving_group)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.solver_label.sizePolicy().hasHeightForWidth())
        self.solver_label.setSizePolicy(sizePolicy)
        self.solver_label.setObjectName(_fromUtf8("solver_label"))
        self.horizontalLayout_6.addWidget(self.solver_label)
        self.solver_selector = QtWidgets.QComboBox(self.solving_group)
        self.solver_selector.setMinimumSize(QtCore.QSize(150, 0))
        self.solver_selector.setObjectName(_fromUtf8("solver_selector"))
        self.horizontalLayout_6.addWidget(self.solver_selector)
        spacerItem12 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_6.addItem(spacerItem12)
        self.verticalLayout_8.addLayout(self.horizontalLayout_6)
        self.incremental_solving_checkbox = QtWidgets.QCheckBox(self.solving_group)
        self.incremental_solving_checkbox.setObjectName(_fromUtf8("incremental_solving_checkbox"))
        self.verticalLayout_8.addWidget(self.incremental_solving_checkbox)
        self.horizontalLayout_9 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_9.setObjectName(_fromUtf8("horizontalLayout_9"))
        self.timeout_label = QtWidgets.QLabel(self.solving_group)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.timeout_label.sizePolicy().hasHeightForWidth())
        self.timeout_label.setSizePolicy(sizePolicy)
        self.timeout_label.setObjectName(_fromUtf8("timeout_label"))
        self.horizontalLayout_9.addWidget(self.timeout_label)
        self.timeout_spinbox = QtWidgets.QSpinBox(self.solving_group)
        self.timeout_spinbox.setObjectName(_fromUtf8("timeout_spinbox"))
        self.horizontalLayout_9.addWidget(self.timeout_spinbox)
        self.sec_label = QtWidgets.QLabel(self.solving_group)
        self.sec_label.setObjectName(_fromUtf8("sec_label"))
        self.horizontalLayout_9.addWidget(self.sec_label)
        spacerItem13 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_9.addItem(spacerItem13)
        self.verticalLayout_8.addLayout(self.horizontalLayout_9)
        self.verticalLayout_5.addWidget(self.solving_group)
        self.optimizations_group = QtWidgets.QGroupBox(self.analysis_group)
        self.optimizations_group.setObjectName(_fromUtf8("optimizations_group"))
        self.verticalLayout_9 = QtWidgets.QVBoxLayout(self.optimizations_group)
        self.verticalLayout_9.setObjectName(_fromUtf8("verticalLayout_9"))
        self.cstprop_checkbox = QtWidgets.QCheckBox(self.optimizations_group)
        self.cstprop_checkbox.setObjectName(_fromUtf8("cstprop_checkbox"))
        self.verticalLayout_9.addWidget(self.cstprop_checkbox)
        self.rebase_checkbox = QtWidgets.QCheckBox(self.optimizations_group)
        self.rebase_checkbox.setObjectName(_fromUtf8("rebase_checkbox"))
        self.verticalLayout_9.addWidget(self.rebase_checkbox)
        self.row_checkbox = QtWidgets.QCheckBox(self.optimizations_group)
        self.row_checkbox.setObjectName(_fromUtf8("row_checkbox"))
        self.verticalLayout_9.addWidget(self.row_checkbox)
        self.verticalLayout_5.addWidget(self.optimizations_group)
        self.verticalLayout.addWidget(self.analysis_group)
        self.scrollArea.setWidget(self.scrollAreaWidgetContents)
        self.verticalLayout_2.addWidget(self.scrollArea)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.load_config_button = QtWidgets.QPushButton(self.verticalLayoutWidget_2)
        self.load_config_button.setObjectName(_fromUtf8("load_config_button"))
        self.horizontalLayout_2.addWidget(self.load_config_button)
        self.save_config_button = QtWidgets.QPushButton(self.verticalLayoutWidget_2)
        self.save_config_button.setObjectName(_fromUtf8("save_config_button"))
        self.horizontalLayout_2.addWidget(self.save_config_button)
        self.generate_config_button = QtWidgets.QPushButton(self.verticalLayoutWidget_2)
        self.generate_config_button.setObjectName(_fromUtf8("generate_config_button"))
        self.horizontalLayout_2.addWidget(self.generate_config_button)
        self.trigger_analysis_button = QtWidgets.QPushButton(self.verticalLayoutWidget_2)
        self.trigger_analysis_button.setObjectName(_fromUtf8("trigger_analysis_button"))
        self.horizontalLayout_2.addWidget(self.trigger_analysis_button)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)
        self.verticalLayout_3.addWidget(self.splitter)
        QtCore.QMetaObject.connectSlotsByName(Analysis)
        Analysis.setWindowTitle(_translate("Analysis", "Analysis", None))
        self.configuration_label.setText(_translate("Analysis", "Configuration", None))
        self.common_group.setToolTip(_translate("Analysis", "Common parameters for both Pinsec and Binsec", None))
        self.common_group.setTitle(_translate("Analysis", "Common", None))
        self.input_label.setText(_translate("Analysis", "Inputs:", None))
        self.initial_state_label.setText(_translate("Analysis", "Initial state:", None))
        self.initial_state_from.setText(_translate("Analysis", "From:", None))
        self.initial_state_to_label.setText(_translate("Analysis", "To:", None))
        self.pinsec_group.setTitle(_translate("Analysis", "Pinsec", None))
        self.bp_label.setText(_translate("Analysis", "Breakpoints:", None))
        self.start_label.setText(_translate("Analysis", "Start:", None))
        self.detect_start_button.setToolTip(_translate("Analysis", "Detect starting point (find the main)", None))
        self.stop_label.setText(_translate("Analysis", "Stop:", None))
        self.detect_stop_button.setToolTip(_translate("Analysis", "Detect the ending point (last instruction of the main)", None))
        self.start_entrypoint_checkbox.setToolTip(_translate("Analysis", "If checked start at the entry point (invalid start,stop)", None))
        self.start_entrypoint_checkbox.setText(_translate("Analysis", "start at entrypoint (-start-entrypoint)", None))
        self.trace_waves_checkbox.setToolTip(_translate("Analysis", "Track self-modifications in the program", None))
        self.trace_waves_checkbox.setText(_translate("Analysis", "Track SMC waves (-trace-wave)", None))
        self.antidebug_checkbox.setText(_translate("Analysis", "anti-debug bypass", None))
        self.analysis_group.setTitle(_translate("Analysis", "Analysis", None))
        self.analysis_name_label.setText(_translate("Analysis", "Analysis:", None))
        self.analysis_name_selector.setToolTip(_translate("Analysis", "Selector for the analysis to perform", None))
        self.direction_label.setText(_translate("Analysis", "Direction:", None))
        self.k_label.setText(_translate("Analysis", "k:", None))
        self.callcvt_label.setText(_translate("Analysis", "Call cvt:", None))
        self.callcvt_selector.setToolTip(_translate("Analysis", "Call convention employed in the program (used for libcall stubs)", None))
        self.trace_input_label.setText(_translate("Analysis", "Trace input:", None))
        self.remote_radiobutton.setToolTip(_translate("Analysis", "The trace is located on the Binsec host", None))
        self.remote_radiobutton.setText(_translate("Analysis", "Remote", None))
        self.local_radiobutton.setToolTip(_translate("Analysis", "Trace located locally on IDA host (IDASec → Binsec)", None))
        self.local_radiobutton.setText(_translate("Analysis", "Local", None))
        self.stream_radiobutton.setToolTip(_translate("Analysis", "Trace will be streamed from Pinsec to Binsec via IDASec", None))
        self.stream_radiobutton.setText(_translate("Analysis", "Stream", None))
        self.trace_label.setText(_translate("Analysis", "Trace:", None))
        self.callmap_checkbox.setToolTip(_translate("Analysis", "Compute the map of calls (use only in specific cases)", None))
        self.callmap_checkbox.setText(_translate("Analysis", "Compute callmap", None))
        self.verbosity_label.setText(_translate("Analysis", "Verbosity:", None))
        self.analysis_specific_group.setTitle(_translate("Analysis", "Analysis specific", None))
        self.cocnsymb_group.setTitle(_translate("Analysis", "Concretization/Symbolization", None))
        self.policy_label.setText(_translate("Analysis", "Policy:", None))
        self.libcall_label.setToolTip(_translate("Analysis", "Create stubs for certain libraries", None))
        self.libcall_label.setText(_translate("Analysis", "Libcall:", None))
        self.syscall_label.setToolTip(_translate("Analysis", "Create stubs for certain syscalls", None))
        self.syscall_label.setText(_translate("Analysis", "Syscall:", None))
        self.instruction_label.setToolTip(_translate("Analysis", "Create stubs for certain instructions (not decoded)", None))
        self.instruction_label.setText(_translate("Analysis", "Instruction:", None))
        self.default_action_label.setToolTip(_translate("Analysis", "Default action to perform on instruction which semantic cannot be translated", None))
        self.default_action_label.setText(_translate("Analysis", "Default action:", None))
        self.solving_group.setTitle(_translate("Analysis", "Solving", None))
        self.solver_label.setText(_translate("Analysis", "Solver:", None))
        self.incremental_solving_checkbox.setText(_translate("Analysis", "Incremental solving", None))
        self.timeout_label.setText(_translate("Analysis", "Timeout:", None))
        self.sec_label.setText(_translate("Analysis", "sec", None))
        self.optimizations_group.setTitle(_translate("Analysis", "Optimizations", None))
        self.cstprop_checkbox.setText(_translate("Analysis", "Constant propagation", None))
        self.rebase_checkbox.setText(_translate("Analysis", "Rebase", None))
        self.row_checkbox.setText(_translate("Analysis", "Read-Over-Write", None))
        self.load_config_button.setText(_translate("Analysis", "Load", None))
        self.save_config_button.setText(_translate("Analysis", "Save", None))
        self.generate_config_button.setText(_translate("Analysis", "Generate", None))
        self.trigger_analysis_button.setText(_translate("Analysis", "Start analysis", None))

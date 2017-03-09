# coding: utf8

import base64
import json

from PyQt5 import QtCore, QtWidgets
import idautils
import idc
from path import Path

import idasec.proto.common_pb2 as common_pb2
import idasec.proto.instruction_pb2 as instruction_pb2
import idasec.proto.libcall_pb2 as libcall_pb2
import idasec.proto.syscall_pb2 as syscall_pb2
from idasec.analysis.default_analysis import STATIC, STATIC_AND_DYNAMIC
from idasec.proto.config_pb2 import input_t
from idasec.protobuf_json import json2pb, pb2json
from idasec.ui.analysis_ui import Ui_Analysis
from idasec.ui.custom_widgets import ButtonLineEdit
from idasec.utils import register_name_to_size, hex_to_bin, to_hex


class AnalysisWidget(QtWidgets.QWidget, Ui_Analysis):
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
        self.pinsec_group.setVisible(False)

        # --- Initialize input table
        self.input_header_table = ["type", "where", "addr/name", "value", "action", "when"]
        self.inputs_table.setColumnCount(len(self.input_header_table))
        self.inputs_table.setHorizontalHeaderLabels(self.input_header_table)
        self.inputs_table.horizontalHeader().setStretchLastSection(True)
        self.inputs_table.horizontalHeader().setSectionResizeMode(self.inputs_table.horizontalHeader().ResizeToContents)
        self.inputs_table.keyPressEvent = self.input_item_keypressed
        self.initial_state_list.keyPressEvent = self.initial_state_keypressed

        # --- Initialize policy table
        self.policy_header_table = ["loc", "inst", "exp", u"Σ", u"ρ"]
        self.policy_table.setColumnCount(len(self.policy_header_table))
        self.policy_table.setHorizontalHeaderLabels(self.policy_header_table)
        self.policy_table.horizontalHeader().setSectionResizeMode(self.policy_table.horizontalHeader().ResizeToContents)

        # --- Initialize events
        self.add_input_button.clicked.connect(self.add_input_action)
        self.add_initial_state_button.clicked.connect(self.add_initial_state_action)
        self.add_bp_button.clicked.connect(self.add_bp_action)
        self.remove_bp_button.clicked.connect(self.remove_bp_action)
        self.detect_start_button.clicked.connect(self.detect_start_action)
        self.detect_stop_button.clicked.connect(self.detect_stop_action)
        self.analysis_name_selector.currentIndexChanged[str].connect(self.analysis_name_changed)
        self.direction_selector.currentIndexChanged[str].connect(self.direction_selector_changed)
        self.local_radiobutton.toggled.connect(self.local_radiobutton_toggled)
        self.policy_selector.currentIndexChanged[str].connect(self.policy_selector_changed)
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

        # --- Fill some Widgets
        self.direction_selector.addItems(["Forward", "Backward"])
        self.callcvt_selector.addItems(["cdecl", "stdcall", "fastcall", "thiscall"])
        self.policy_selector.addItems(["Custom", "CC", "CS", "SC", "SSe", "SS"])
        self.default_action_selector.addItems(["CONC", "SYMB"])
        self.solver_selector.addItems(["auto"])

    def add_input_action(self):
        self.inputs_table.setRowCount(self.inputs_table.rowCount()+1)
        i = self.inputs_table.rowCount()-1
        type_combo = QtWidgets.QComboBox()
        type_combo.addItems(["REG", "MEM"])
        action_combo = QtWidgets.QComboBox()
        action_combo.addItems(["DEFAULT", "PATCH", "CONC", "SYMB", "IGNORE"])
        when_combo = QtWidgets.QComboBox()
        when_combo.addItems(["BEFORE", "AFTER"])
        info = [type_combo, QtWidgets.QTableWidgetItem(), QtWidgets.QTableWidgetItem(), QtWidgets.QTableWidgetItem(),
                action_combo, when_combo]

        for col_id, widget in enumerate(info):
            if isinstance(widget, QtWidgets.QTableWidgetItem):
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
                raw = base64.b64encode(idc.GetManyBytes(from_addr, to_addr-from_addr+1))
                self.initial_state_list.addItem("%x -> %x: %s" % (from_addr, to_addr, raw))
        except ValueError:
            print "From or To cannot be converted to address"

    def initial_state_keypressed(self, event):
        if event.key() == QtCore.Qt.Key_Delete:
            it = self.initial_state_list.takeItem(self.initial_state_list.currentRow())
            del it
        return QtWidgets.QListWidget.keyPressEvent(self.initial_state_list, event)

    def add_bp_action(self):
        res = idc.AskAddr(idc.here(), "Breakpoint address:")
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

    def detect_start_and_stop(self):  # FIXME:Duplicate code with core (or something similar)
        start, stop = 0, 0
        if self.core.ftype == "PE":
            start, stop = self.core.fun_mapping["start"]
        else:
            if "main" in self.core.fun_mapping:
                start, stop = self.core.fun_mapping["main"]
            elif "start" in self.core.fun_mapping:
                if "__libc_start_main" in self.core.fun_mapping:
                    instrs = list(idautils.FuncItems(self.core.fun_mapping["start"][0]))
                    instrs.reverse()
                    for inst in instrs:
                        arg1 = idc.GetOperandValue(inst, 0)
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
            self.analysis_specific_group.setTitle(name+" configuration")
            analysis_class.on_analysis_selected(self)  # Allow the analysis to perform some processing on the widget
        else:
            self.analysis_specific_group.setVisible(False)

    def direction_selector_changed(self, name):
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
                       "SSe": [["*", "*", "esp", "*", "Pc"],
                               ["*", "*", "ebp", "*", "Pc"],
                               ["default", "", "", "", "P"]],
                       "SS": [["default", "", "", "", "P"]]}
            for line in mapping[name]:
                i = self.add_policy_item_action()
                self.set_policy_item_values(i, line)

    def add_policy_item_action(self):
        self.policy_table.setRowCount(self.policy_table.rowCount()+1)
        i = self.policy_table.rowCount()-1
        btn1 = ButtonLineEdit(['*', "'addr'", "[addr1..addr2]", "default"])
        btn2 = ButtonLineEdit(["*", " _ := _", "goto _"])
        btn3 = ButtonLineEdit(["*", "expr", "expr1 <: expr2"])
        btn4 = ButtonLineEdit(["*", "istainted(_)", "term1 && term2", "term1 || term2"])
        btn5 = QtWidgets.QComboBox()
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
        QtWidgets.QMessageBox.about(self, u"Policy help", u"Nothing into yet..")

    def add_libcall_action(self):
        already_added = [self.libcall_selector.itemText(x) for x in xrange(self.libcall_selector.count())]
        items = [x for x in self.libcalls if x not in already_added]
        if len(items) == 0:
            print "Nothing else to add"
        else:
            lib, ok = QtWidgets.QInputDialog.getItem(self, "Libcall selector", "Libcall stub to add:", items)
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
            sys, ok = QtWidgets.QInputDialog.getItem(self, "Syscall selector", "Syscall stub to add:", items)
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
            sys, ok = QtWidgets.QInputDialog.getItem(self, "Instruction selector", "Instruction stub to add:", items)
            if ok:
                self.instruction_selector.addItem(sys)

    def remove_instr_action(self):
        self.instruction_selector.removeItem(self.instruction_selector.currentIndex())

    def load_config_clicked(self):
        filename = QtWidgets.QFileDialog.getOpenFileName()[0]
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
        if "start" in json_data:
            self.start_field.setText(hex(json_data["start"]))
        if "stop" in json_data:
            self.stop_field.setText(hex(json_data["stop"]))
        if "libcalls" in json_data:
            for lib in [x for x in json_data["libcalls"] if x["name"] in self.libcalls]:
                self.libcall_selector.addItem(lib["name"])
        if "syscalls" in json_data:
            for lib in [x for x in json_data["syscalls"] if x["name"] in self.syscalls]:
                self.syscall_selector.addItem(lib["name"])
        if "instrs" in json_data:
            for i in [x for x in json_data["instrs"] if x["ident"].lower() in self.instructions]:
                self.instruction_selector.addItem(i["ident"].lower())
        if "policy" in json_data:
            for pol in json_data["policy"]:
                i = self.add_policy_item_action()
                split = pol.split(" => ")
                split2 = split[0].split("::")
                if len(split2) == 1:
                    self.set_policy_item_values(i, [split[0], "", "", "", split[1]])
                else:
                    self.set_policy_item_values(i, split2+[split[1]])
        if "inputs" in json_data:
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
                    value = {"BIT8": reg["value_8"], "BIT16": reg["value_16"], "BIT32": reg["value_32"],
                             "BIT64": reg["value_64"], "BIT80": reg["value_80"], "BIT128": reg["value_128"],
                             "BIT256": reg["value_256"]}[reg["typeid"]]
                    if isinstance(value, int):
                        self.inputs_table.item(i, 3).setText(hex(value))
                    else:
                        self.inputs_table.item(i, 3).setText(to_hex(value))
                else:
                    self.inputs_table.item(i, 2).setText(hex(input["mem"]["addr"]))
                    self.inputs_table.item(i, 3).setText(to_hex(base64.b64decode(input["mem"]["value"])))
        if "breakpoints" in json_data:
            for bp in json_data["breakpoints"]:
                self.bp_list.addItem(hex(bp))
        if "initial_state" in json_data:
            for item in json_data["initial_state"]:
                self.initial_state_list.addItem("%x -> %x: %s" %(item["addr"], item["addr"]+len(item["value"]), item["value"]))
        if "direction" in json_data:
            self.direction_selector.setCurrentIndex(self.direction_selector.findText(json_data["direction"].title()))
        if "callcvt" in json_data:
            self.callcvt_selector.setCurrentIndex(self.callcvt_selector.findText(json_data["callcvt"].lower()))
        if "ksteps" in json_data:
            self.k_spinbox.setValue(json_data["ksteps"])
        if "analysis_name" in json_data:
            self.analysis_name_selector.setCurrentIndex(self.analysis_name_selector.findText(json_data["analysis_name"]))
        if "solver" in json_data:
            index = self.solver_selector.findText(json_data["solver"])
            if index != -1:
                self.solver_selector.setCurrentIndex(index)
        if "incremental" in json_data:
            self.incremental_solving_checkbox.setChecked(json_data["incremental"])
        if "timeout" in json_data:
            self.timeout_spinbox.setValue(json_data["timeout"])
        if "optim_cstprop" in json_data:
            self.cstprop_checkbox.setChecked(json_data["optim_cstprop"])
        if "optim_rebase" in json_data:
            self.rebase_checkbox.setChecked(json_data["optim_rebase"])
        if "optim_row" in json_data:
            self.row_checkbox.setChecked(json_data["optim_row"])
        if "default_action" in json_data:
            self.default_action_selector.setCurrentIndex(self.default_action_selector.findText(json_data["default_action"]))
        if "verbosity" in json_data:
            self.verbosity_slider.setValue(json_data["verbosity"])
        if "additional_parameters" in json_data:
            analyse = self.parent.analysis_from_name(json_data["additional_parameters"]["typeid"])
            analyse.config_widget.set_fields(json_data["additional_parameters"])

        self.configuration_textarea.setText(raw)
        # -------

    def set_policy_values(self, i, values):
        for col_id, value in enumerate(values):
            if col_id == len(values)-1:
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
                    filename = QtWidgets.QFileDialog.getSaveFileName()[0]
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

        # -- Add inputs
        for row in xrange(self.inputs_table.rowCount()):
            input = self.core.configuration.inputs.add()
            widg = [self.inputs_table.item(row, x) if x in [1, 2, 3] else self.inputs_table.cellWidget(row, x)
                    for x in xrange(self.inputs_table.columnCount())]
            type, where, addr_name, value, action, when = widg[0].currentText(), widg[1].text(), widg[2].text(),\
                                                          widg[3].text(), widg[4].currentText(), widg[5].currentText()
            input.typeid, input.action, input.when = getattr(input_t, type), getattr(common_pb2, action),\
                                                     getattr(input_t, when)
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
                else: # MEM
                    addr_name = int(addr_name, 16) if addr_name.startswith("0x") else int(addr_name)
                    input.mem.addr = addr_name
                    input.mem.value = hex_to_bin(value)
            except ValueError:
                print "Invalid field in row %d of inputs" % row
                self.core.configuration.inputs.remove(input)
        # ---------

        # -- Initial state
        for from_addr, to_addr in [[int(y.split(":")[0], 16) for y in self.initial_state_list.item(x).text().split(" -> ")]
                                   for x in xrange(self.initial_state_list.count())]:
            mem = self.core.configuration.initial_state.add()
            mem.addr = from_addr
            bytes = idc.GetManyBytes(from_addr, to_addr-from_addr+1)
            if bytes is None:
                print "Cannot retrieve bytes from %x to %x for initial state" % (from_addr, to_addr)
            else:
                mem.value = bytes
        # ----------------

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

        if self.callmap_checkbox.isChecked(): # FIXME: Duplicate code with something else.
            imports = self.core.seg_mapping[".idata"] if self.core.ftype == "PE" else self.core.seg_mapping['.plt']
            start, stop = self.core.seg_mapping[".text"]
            current = start
            while current <= stop:
                inst = current
                if idc.GetMnem(inst) in ["call", "jmp"]:
                    value = idc.GetOperandValue(inst, 0)
                    name = idc.GetOpnd(inst, 0)
                    if imports[0] <= value <= imports[1]:
                        entry = self.core.configuration.call_map.add()
                        entry.address = inst
                        entry.name = name
                current = idc.NextHead(current, stop)

        # -- Policy generation --
        for row in xrange(self.policy_table.rowCount()):
            count = self.policy_table.columnCount()
            elts = [self.policy_table.cellWidget(row, x).currentText() if x == count-1 else
                    self.policy_table.cellWidget(row, x).text() for x in xrange(count)]
            if elts[0] == "default":
                s = elts[0]+" => "+elts[4]
            else:
                s = "%s :: %s :: %s :: %s => %s" % (elts[0], elts[1], elts[2], elts[3], elts[4])
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
            # TODO: Set the ID + IDENT
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
        # -------------------

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

        # -- Now generate !
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

        name = self.core.configuration.analysis_name
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
                    id = int(self.trace_selector.currentText().split(" ")[0][1:])  # TODO: find another to get trace id
                    trace = self.core.traces[id]
                    self.parent.start_analysis(name, self.core.configuration, trace=trace)

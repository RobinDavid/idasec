# coding: utf8

from PyQt5 import QtCore, QtWidgets
from path import Path
from idasec.trace import Trace
from google.protobuf.message import DecodeError

from idasec.ui.trace_ui import Ui_trace_form

import idc
import idaapi


import idasec.ui.resources_rc


class TraceWidget(QtWidgets.QWidget, Ui_trace_form):
    def __init__(self, parent):
        super(TraceWidget, self).__init__()
        self.parent = parent
        self.name = "TraceWidget"
        self.core = self.parent.core
        self.broker = self.core.broker
        self.colorized = False
        self.heatmaped = False
        self.trace_header_table = ["#","Addr","Instruction"] #,"Th","Routine"
        self.index_map = {}
        self.id_map = {}
        self.OnCreate(self)

    def OnCreate(self, form):
        self.setupUi(self)
        #self.connect(self.add_trace_button, QtCore.SIGNAL("clicked()"), self.load_trace)
        self.add_trace_button.clicked.connect(self.load_trace)
        #self.connect(self.disassemble_button, QtCore.SIGNAL("clicked()"), self.disassemble_from_trace)
        self.disassemble_button.clicked.connect(self.disassemble_from_trace)
        #self.connect(self.colorize_button, QtCore.SIGNAL("clicked()"), self.colorize_trace)
        self.colorize_button.clicked.connect(self.colorize_trace)
        #self.connect(self.heatmap_button, QtCore.SIGNAL("clicked()"), self.heatmap_trace)
        self.heatmap_button.clicked.connect(self.heatmap_trace)
        #self.connect(self.dump_button, QtCore.SIGNAL("clicked()"), self.dump_trace)
        self.dump_button.clicked.connect(self.dump_trace)
        #self.connect(self.refresh_button, QtCore.SIGNAL("clicked()"), self.refresh_trace_view)
        self.refresh_button.clicked.connect(self.refresh_trace_view)
        #self.connect(self.traces_tab, QtCore.SIGNAL('currentChanged(int)'), self.trace_switch)
        self.traces_tab.currentChanged.connect(self.trace_switch)
        #self.connect(self.traces_tab, QtCore.SIGNAL('tabCloseRequested(int)'), self.unload_trace)
        self.traces_tab.tabCloseRequested.connect(self.unload_trace)
        self.loading_stat.setVisible(False)
        self.progressbar_loading.setVisible(False)
        self.traces_tab.setTabsClosable(True)
        #self.reads_view.headerItem().setHidden(True)
        #self.writes_view.headerItem().setHidden(True)
        self.reads_view.setHeaderItem(QtWidgets.QTreeWidgetItem(["name", "value"]))
        self.writes_view.setHeaderItem(QtWidgets.QTreeWidgetItem(["name", "value"]))

    def go_to_instruction(self, item):
        table = self.index_map[self.traces_tab.currentIndex()]
        addr_item = table.item(item.row(), 1)
        addr_s = addr_item.text()
        try:
            addr = int(addr_s, 0)
            idc.Jump(addr)
        except Exception:
            print "Cannot jump to the selected location"


    def load_trace(self):
        filename = QtWidgets.QFileDialog.getOpenFileName()[0]
        filepath = Path(filename)

        if filepath.exists() and filepath.isfile():
            trace = Trace(filename)
            try:
                #==== Gui stuff
                self.loading_stat.setVisible(True)
                self.progressbar_loading.setVisible(True)
                self.progressbar_loading.reset()
                self.progressbar_loading.setMaximum(filepath.getsize())

                newtable = QtWidgets.QTableWidget(self)
                newtable.verticalHeader().setVisible(False)
                newtable.setColumnCount(len(self.trace_header_table))
                newtable.setHorizontalHeaderLabels(self.trace_header_table)
                newtable.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
                newtable.currentItemChanged.connect(self.update_instruction_informations)
                newtable.itemDoubleClicked.connect(self.go_to_instruction)
                index = self.traces_tab.addTab(newtable, filepath.name)
                id = self.parent.add_trace(trace)
                self.id_map[index] = id
                self.index_map[index] = newtable
                self.traces_tab.setCurrentIndex(index)
                #=====
                total_instr = 0
                nb_row = 0
                current_size = 0
                for chk, sz_chk, i, j, sz in trace.parse_file_generator(filename):
                    total_instr += j-i
                    current_size += sz
                    self.loading_stat.setText("Chunk nb:"+str(chk)+" | Instr nb:"+str(total_instr))
                    self.loading_stat.adjustSize()
                    self.progressbar_loading.setValue(current_size)
                    newtable.setRowCount(nb_row+sz_chk)
                    self.add_chunk_trace_table(newtable, trace, i, nb_row)
                    nb_row += sz_chk
                    newtable.scrollToBottom()

                self.trace_switch(index)

                #===== Gui stuff
                newtable.scrollToTop()
                self.loading_stat.setVisible(False)
                self.progressbar_loading.setVisible(False)
                #============
            except DecodeError:
                print "Fail to parse the given trace"
        else:
            print "File not existing or not a file"

    def add_chunk_trace_table(self, table, trace, k, index):
        i = index
        while trace.instrs.has_key(k):
            inst = trace.instrs[k]
            if trace.metas.has_key(k):
                for name, arg1, arg2 in trace.metas[k]:
                    if name == "wave":
                        infos = ["=","========","> Wave:"+str(arg1)] #,"=","========"
                    elif name == "exception":
                        infos = ["","","Exception type:"+str(arg1)+" @handler:"+str(arg2)] #,"",""
                    elif name == "module":
                        infos = ["","Module",arg1] #,"",""
                    else:
                        infos = ["","","Invalid"]#,"",""
                    for col_id, cell in enumerate(infos):
                        newitem = QtWidgets.QTableWidgetItem(cell)
                        newitem.setFlags(newitem.flags() ^ QtCore.Qt.ItemIsEditable)
                        table.setItem(i, col_id, newitem)
                    i += 1
            info = [str(k), hex(inst.address)[:-1], inst.opcode] #str(inst.thread), idc.GetFunctionName(inst.address)
            for col_id, cell in enumerate(info):
                newitem = QtWidgets.QTableWidgetItem(cell)
                newitem.setFlags(newitem.flags() ^ QtCore.Qt.ItemIsEditable)
                table.setItem(i, col_id, newitem)
            i += 1
            k += 1

    def trace_switch(self, index, trace=None):
        try:
            trace = self.core.traces[self.id_map[index]] if trace is None else trace
            fname = Path(trace.filename).name
            length = trace.length()
            uniq = len(trace.addr_covered)
            try:
                coverage = (uniq * 100) / self.core.nb_instr
            except ZeroDivisionError:
                coverage = -1
            self.trace_infos.setText(("Name:%s\nLength:%d\nUnique instr:%d\nCoverage:%d%c" % (fname, length, uniq, coverage, '%')))
        except KeyError: #Upon tab creation callback called while id_map not yet filled
            pass

    def unload_trace(self, index):
        self.traces_tab.removeTab(index)
        tr_id = self.id_map[index]
        table = self.index_map[index]
        table.clear()
        del table
        self.index_map.pop(index)
        self.id_map.pop(index)
        self.parent.remove_trace(tr_id)
        if self.traces_tab.currentIndex() == -1:
            self.trace_infos.clear()
        print "unload trace"

    def update_instruction_informations(self, new_item, old_item):
        index = self.traces_tab.currentIndex()
        try:
            table = self.index_map[index]
            trace = self.core.traces[self.id_map[index]]
            offset = int(table.item(new_item.row(), 0).text())
            inst = trace.instrs[offset]

            #=== Gui stuff
            self.reads_view.clear()
            self.writes_view.clear()
            self.additional_infos.clear()
            for r_w, name, value in inst.registers:
                val_s = hex(value)[:-1] if hex(value).endswith('L') else hex(value)
                infos = [name, val_s]
                widget = QtWidgets.QTreeWidgetItem(infos)
                if r_w == "R":
                    self.reads_view.addTopLevelItem(widget)
                else:
                    self.writes_view.addTopLevelItem(widget)
            for r_w, addr, value in inst.memories:
                infos = ["@[%x]"%addr, "".join("{:02x}".format(ord(c)) for c in value)]
                widget = QtWidgets.QTreeWidgetItem(infos)
                if r_w == "R":
                    self.reads_view.addTopLevelItem(widget)
                else:
                    self.writes_view.addTopLevelItem(widget)
            for i in range(self.reads_view.topLevelItemCount()):
                self.reads_view.resizeColumnToContents(i)
            for i in range(self.writes_view.topLevelItemCount()):
                self.writes_view.resizeColumnToContents(i)

            if inst.nextaddr is not None:
                self.additional_infos.setHtml("Next addr:<bold>"+hex(inst.nextaddr)[:-1]+"</bold>")
            if inst.wave is not None:
                self.additional_infos.append("Wave: "+str(inst.wave))
            if inst.syscall is not None:
                self.additional_infos.append("Syscall:"+str(inst.syscall.id))
            if inst.libcall is not None:
                c = inst.libcall
                s = "Libcall:<span style='color:blue;'>"+str(c.func_name)+"</span>"
                s += "<ul><li>at:"+hex(c.func_addr)[:-1]+"</li>"
                s += "<li>traced: <span style='color:" + ("blue" if c.is_traced else "red")+";'>"+str(c.is_traced)+"</span></li></ul>"
                self.additional_infos.append(s)
            if inst.comment is not None:
                self.additional_infos.append("Comment:"+inst.comment)
        except ValueError:
            pass
        except KeyError:
            pass

    def disassemble_from_trace(self):
        try:
            index = self.traces_tab.currentIndex()
            trace = self.core.traces[self.id_map[index]]

            self.disassemble_button.setFlat(True)
            found_match = False
            for k, inst in trace.instrs.items():
                if trace.metas.has_key(k):
                    for name, arg1, arg2 in trace.metas[k]:
                        if name == "wave":
                            self.parent.log("LOG","Wave n°%d encountered at (%s,%x) stop.." % (arg1, k, inst.address))
                            prev_inst = trace.instrs[k-1]
                            idc.MakeComm(prev_inst.address, "Jump into Wave %d" % arg1)
                            self.disassemble_button.setFlat(False)
                            return
                #TODO: Check that the address is in the address space of the program
                if not idc.isCode(idc.GetFlags(inst.address)):
                    found_match = True
                    #TODO: Add an xref with the previous instruction
                    self.parent.log("LOG", "Addr:%x not decoded as an instruction" % inst.address)
                    if idc.MakeCode(inst.address) == 0:
                        self.parent.log("ERROR", "Fail to decode at:%x" % inst.address)
                    else:
                        idaapi.autoWait()
                        self.parent.log("SUCCESS", "Instruction decoded at:%x" % inst.address)

            if not found_match:
                self.parent.log("LOG", "All instruction are already decoded")
            self.disassemble_button.setFlat(False)
        except KeyError:
            print "No trace found to use"

    def colorize_trace(self):
        try:
            index = self.traces_tab.currentIndex()
            trace = self.core.traces[self.id_map[index]]
            if self.colorized:
                self.colorize_button.setText("Colorize trace")
                color = 0xffffff
            else:
                self.colorize_button.setText("Uncolorize trace")
                self.colorize_button.setFlat(True)
                color = 0x98FF98
            for inst in trace.instrs.values():
                if idc.isCode(idc.GetFlags(inst.address)):
                    idc.SetColor(inst.address, idc.CIC_ITEM, color)
            if not self.colorized:
                self.colorize_button.setFlat(False)
                self.colorized = True
            else:
                self.colorized = False

        except KeyError:
            print "No trace found"

    def heatmap_trace(self):
        try:
            index = self.traces_tab.currentIndex()
            trace = self.core.traces[self.id_map[index]]
            if self.heatmaped:
                self.heatmap_button.setText("Heatmap")
                color = lambda x: 0xffffff
            else:
                self.heatmap_button.setText("Heatmap undo")
                self.heatmap_button.setFlat(True)
                hit_map = trace.address_hit_count
                color_map = self.compute_step_map(set(hit_map.values()))
                print color_map
                color = lambda x: color_map[hit_map[x]]
            for inst in trace.instrs.values():
                if idc.isCode(idc.GetFlags(inst.address)):
                    c = color(inst.address)
                    idc.SetColor(inst.address, idc.CIC_ITEM, c)
            if not self.heatmaped:
                self.heatmap_button.setFlat(False)
                self.heatmaped = True
            else:
                self.heatmaped = False
        except KeyError:
            print "No trace found"

    def compute_step_map(self, hit_map):
        max = 400
        if len(hit_map)+1 > 510:
            max = 510
        step_float = max / (len(hit_map)+1)
        hit_map.add(0)
        step_map = {}
        for i, hit_value in enumerate(hit_map):
            step_value = int(i * step_float)
            print "Step:", step_value
            if step_value > 255:
                color = int('%02x%02x%02x' % (0, 0, 255 - (step_value - 255)), 16)
            else:
                color = int('%02x%02x%02x' % (255 - step_value, 255 - step_value, 255), 16)
            step_map[hit_value] = color
        step_map[0] = 0xffffff
        return step_map

    def dump_trace(self):
        filename = QtWidgets.QFileDialog.getSaveFileName()[0]
        filepath = Path(filename)
        if not filepath.exists() and filepath != '':
            try:
                index = self.traces_tab.currentIndex()
                trace = self.core.traces[self.id_map[index]]
                f = filepath.open("w")
                for line in trace.to_string_generator():
                    f.write(line+"\n")
                f.close()
                print "Writing done"
            except KeyError:
                print "Trace not found"
        else:
            print "File already exists.. (do not dump)"

    def refresh_trace_view(self):
        index = self.traces_tab.currentIndex()
        try:
            table = self.index_map[index]
            for i in xrange(table.rowCount()):
                addr_item = table.item(i, 1)
                addr = int(addr_item.text(), 0)
                routine_item = table.item(i, 3)
                routine_item.setText(idc.GetFunctionName(addr))
            print "Refresh done"
        except KeyError:
            print "Trace not found"


    def OnClose(self, form):
        print("Closed invoked !")
        pass

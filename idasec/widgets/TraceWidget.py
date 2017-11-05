# coding: utf8

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QFileDialog, QTableWidgetItem, QTreeWidgetItem
from PyQt5.QtCore import Qt
from idasec.path import Path
from idasec.trace import Trace
from google.protobuf.message import DecodeError


import idc
import idaapi


import idasec.ui.resources_rc

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

class TraceWidget(QtWidgets.QWidget):
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
        self.add_trace_button.clicked.connect(self.load_trace)
        self.disassemble_button.clicked.connect(self.disassemble_from_trace)
        self.colorize_button.clicked.connect(self.colorize_trace)
        self.heatmap_button.clicked.connect(self.heatmap_trace)
        self.dump_button.clicked.connect(self.dump_trace)
        self.refresh_button.clicked.connect(self.refresh_trace_view)
        self.traces_tab.currentChanged.connect(self.trace_switch)
        self.traces_tab.tabCloseRequested.connect(self.unload_trace)
        self.loading_stat.setVisible(False)
        self.progressbar_loading.setVisible(False)
        self.traces_tab.setTabsClosable(True)
        #self.reads_view.headerItem().setHidden(True)
        #self.writes_view.headerItem().setHidden(True)
        self.reads_view.setHeaderItem(QTreeWidgetItem(["name", "value"]))
        self.writes_view.setHeaderItem(QTreeWidgetItem(["name", "value"]))

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
        filename =  QFileDialog.getOpenFileName()[0]
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
                newtable.horizontalHeader().setStretchLastSection(True)
                newtable.horizontalHeader().sectionResizeMode(newtable.horizontalHeader().ResizeToContents)
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
                        newitem = QTableWidgetItem(cell)
                        newitem.setFlags(newitem.flags() ^ Qt.ItemIsEditable)
                        table.setItem(i, col_id, newitem)
                    i += 1
            info = [str(k), hex(inst.address)[:-1], inst.opcode] #str(inst.thread), idc.GetFunctionName(inst.address)
            for col_id, cell in enumerate(info):
                newitem = QTableWidgetItem(cell)
                newitem.setFlags(newitem.flags() ^ Qt.ItemIsEditable)
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
                widget = QTreeWidgetItem(infos)
                if r_w == "R":
                    self.reads_view.addTopLevelItem(widget)
                else:
                    self.writes_view.addTopLevelItem(widget)
            for r_w, addr, value in inst.memories:
                infos = ["@[%x]"%addr, "".join("{:02x}".format(ord(c)) for c in value)]
                widget = QTreeWidgetItem(infos)
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
                s += "<li>traced: <span style='color:"+ ("blue" if c.is_traced else "red")+";'>"+str(c.is_traced)+"</span></li></ul>"
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
            previous = None
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
                previous = inst

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
        filename =  QFileDialog.getSaveFileName()[0]
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

    def setupUi(self, trace_form):
        def _fromUtf8(s):
            return s
        def _translate(x,y,z):
            return y
        trace_form.setObjectName(_fromUtf8("trace_form"))
        trace_form.resize(799, 556)
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(trace_form)
        self.verticalLayout_3.setObjectName(_fromUtf8("verticalLayout_3"))
        self.splitter = QtWidgets.QSplitter(trace_form)
        self.splitter.setOrientation(QtCore.Qt.Horizontal)
        self.splitter.setObjectName(_fromUtf8("splitter"))
        self.verticalLayoutWidget = QtWidgets.QWidget(self.splitter)
        self.verticalLayoutWidget.setObjectName(_fromUtf8("verticalLayoutWidget"))
        self.verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.traces_tab = QtWidgets.QTabWidget(self.verticalLayoutWidget)
        self.traces_tab.setMinimumSize(QtCore.QSize(0, 0))
        self.traces_tab.setObjectName(_fromUtf8("traces_tab"))
        self.verticalLayout.addWidget(self.traces_tab)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.loading_stat = QtWidgets.QLabel(self.verticalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.loading_stat.sizePolicy().hasHeightForWidth())
        self.loading_stat.setSizePolicy(sizePolicy)
        self.loading_stat.setText(_fromUtf8(""))
        self.loading_stat.setObjectName(_fromUtf8("loading_stat"))
        self.horizontalLayout_2.addWidget(self.loading_stat)
        self.progressbar_loading = QtWidgets.QProgressBar(self.verticalLayoutWidget)
        self.progressbar_loading.setProperty("value", 24)
        self.progressbar_loading.setObjectName(_fromUtf8("progressbar_loading"))
        self.horizontalLayout_2.addWidget(self.progressbar_loading)
        self.add_trace_button = QtWidgets.QPushButton(self.verticalLayoutWidget)
        self.add_trace_button.setMinimumSize(QtCore.QSize(0, 30))
        self.add_trace_button.setMaximumSize(QtCore.QSize(30, 30))
        self.add_trace_button.setText(_fromUtf8(""))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/icons/icons/open-iconic-master/png/3x/plus-3x.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.add_trace_button.setIcon(icon)
        self.add_trace_button.setIconSize(QtCore.QSize(14, 14))
        self.add_trace_button.setObjectName(_fromUtf8("add_trace_button"))
        self.horizontalLayout_2.addWidget(self.add_trace_button)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.verticalLayoutWidget_2 = QtWidgets.QWidget(self.splitter)
        self.verticalLayoutWidget_2.setObjectName(_fromUtf8("verticalLayoutWidget_2"))
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_2)
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.trace_infos_title = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.trace_infos_title.sizePolicy().hasHeightForWidth())
        self.trace_infos_title.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setBold(True)
        font.setItalic(False)
        font.setUnderline(False)
        font.setWeight(75)
        self.trace_infos_title.setFont(font)
        self.trace_infos_title.setAlignment(QtCore.Qt.AlignCenter)
        self.trace_infos_title.setObjectName(_fromUtf8("trace_infos_title"))
        self.verticalLayout_2.addWidget(self.trace_infos_title)
        self.trace_infos = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.trace_infos.setMinimumSize(QtCore.QSize(0, 60))
        self.trace_infos.setText(_fromUtf8(""))
        self.trace_infos.setObjectName(_fromUtf8("trace_infos"))
        self.verticalLayout_2.addWidget(self.trace_infos)
        self.line = QtWidgets.QFrame(self.verticalLayoutWidget_2)
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName(_fromUtf8("line"))
        self.verticalLayout_2.addWidget(self.line)
        self.label_3 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_3.sizePolicy().hasHeightForWidth())
        self.label_3.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setAlignment(QtCore.Qt.AlignCenter)
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.verticalLayout_2.addWidget(self.label_3)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName(_fromUtf8("horizontalLayout_4"))
        self.label_6 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_6.sizePolicy().hasHeightForWidth())
        self.label_6.setSizePolicy(sizePolicy)
        self.label_6.setMaximumSize(QtCore.QSize(16777215, 20))
        font = QtGui.QFont()
        font.setUnderline(True)
        self.label_6.setFont(font)
        self.label_6.setAlignment(QtCore.Qt.AlignCenter)
        self.label_6.setObjectName(_fromUtf8("label_6"))
        self.horizontalLayout_4.addWidget(self.label_6)
        self.label_5 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_5.sizePolicy().hasHeightForWidth())
        self.label_5.setSizePolicy(sizePolicy)
        self.label_5.setMaximumSize(QtCore.QSize(16777215, 20))
        font = QtGui.QFont()
        font.setUnderline(True)
        self.label_5.setFont(font)
        self.label_5.setAlignment(QtCore.Qt.AlignCenter)
        self.label_5.setObjectName(_fromUtf8("label_5"))
        self.horizontalLayout_4.addWidget(self.label_5)
        self.verticalLayout_2.addLayout(self.horizontalLayout_4)
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setObjectName(_fromUtf8("horizontalLayout_6"))
        self.reads_view = QtWidgets.QTreeWidget(self.verticalLayoutWidget_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.reads_view.sizePolicy().hasHeightForWidth())
        self.reads_view.setSizePolicy(sizePolicy)
        self.reads_view.setMinimumSize(QtCore.QSize(0, 0))
        self.reads_view.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.reads_view.setObjectName(_fromUtf8("reads_view"))
        self.reads_view.headerItem().setText(0, _fromUtf8("1"))
        self.horizontalLayout_6.addWidget(self.reads_view)
        self.writes_view = QtWidgets.QTreeWidget(self.verticalLayoutWidget_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.writes_view.sizePolicy().hasHeightForWidth())
        self.writes_view.setSizePolicy(sizePolicy)
        self.writes_view.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.writes_view.setObjectName(_fromUtf8("writes_view"))
        self.writes_view.headerItem().setText(0, _fromUtf8("1"))
        self.horizontalLayout_6.addWidget(self.writes_view)
        self.verticalLayout_2.addLayout(self.horizontalLayout_6)
        self.additional_infos = QtWidgets.QTextEdit(self.verticalLayoutWidget_2)
        self.additional_infos.setObjectName(_fromUtf8("additional_infos"))
        self.verticalLayout_2.addWidget(self.additional_infos)
        spacerItem = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout_2.addItem(spacerItem)
        self.line_2 = QtWidgets.QFrame(self.verticalLayoutWidget_2)
        self.line_2.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_2.setObjectName(_fromUtf8("line_2"))
        self.verticalLayout_2.addWidget(self.line_2)
        self.label_4 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_4.sizePolicy().hasHeightForWidth())
        self.label_4.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_4.setFont(font)
        self.label_4.setAlignment(QtCore.Qt.AlignCenter)
        self.label_4.setObjectName(_fromUtf8("label_4"))
        self.verticalLayout_2.addWidget(self.label_4)
        self.gridLayout_2 = QtWidgets.QGridLayout()
        self.gridLayout_2.setObjectName(_fromUtf8("gridLayout_2"))
        self.dump_button = QtWidgets.QPushButton(self.verticalLayoutWidget_2)
        self.dump_button.setObjectName(_fromUtf8("dump_button"))
        self.gridLayout_2.addWidget(self.dump_button, 2, 1, 1, 1)
        self.label_9 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_9.setObjectName(_fromUtf8("label_9"))
        self.gridLayout_2.addWidget(self.label_9, 1, 0, 1, 1)
        self.refresh_button = QtWidgets.QPushButton(self.verticalLayoutWidget_2)
        self.refresh_button.setObjectName(_fromUtf8("refresh_button"))
        self.gridLayout_2.addWidget(self.refresh_button, 2, 2, 1, 1)
        self.disassemble_button = QtWidgets.QPushButton(self.verticalLayoutWidget_2)
        self.disassemble_button.setObjectName(_fromUtf8("disassemble_button"))
        self.gridLayout_2.addWidget(self.disassemble_button, 0, 1, 1, 1)
        self.label_10 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_10.setObjectName(_fromUtf8("label_10"))
        self.gridLayout_2.addWidget(self.label_10, 2, 0, 1, 1)
        self.colorize_button = QtWidgets.QPushButton(self.verticalLayoutWidget_2)
        self.colorize_button.setObjectName(_fromUtf8("colorize_button"))
        self.gridLayout_2.addWidget(self.colorize_button, 1, 1, 1, 1)
        self.heatmap_button = QtWidgets.QPushButton(self.verticalLayoutWidget_2)
        self.heatmap_button.setObjectName(_fromUtf8("heatmap_button"))
        self.gridLayout_2.addWidget(self.heatmap_button, 1, 2, 1, 1)
        self.label_8 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_8.setObjectName(_fromUtf8("label_8"))
        self.gridLayout_2.addWidget(self.label_8, 0, 0, 1, 1)
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_2.addItem(spacerItem1, 2, 3, 1, 1)
        self.verticalLayout_2.addLayout(self.gridLayout_2)
        self.verticalLayout_3.addWidget(self.splitter)

        self.traces_tab.setCurrentIndex(-1)
        QtCore.QMetaObject.connectSlotsByName(trace_form)

        trace_form.setWindowTitle(_translate("trace_form", "Trace", None))
        self.trace_infos_title.setText(_translate("trace_form", "Trace infos", None))
        self.label_3.setText(_translate("trace_form", "Instruction infos", None))
        self.label_6.setText(_translate("trace_form", "Read:", None))
        self.label_5.setText(_translate("trace_form", "Write:", None))
        self.label_4.setText(_translate("trace_form", "Trace actions", None))
        self.dump_button.setToolTip(_translate("trace_form", "Save a dump of the trace to a file", None))
        self.dump_button.setText(_translate("trace_form", "Dump to file", None))
        self.label_9.setText(_translate("trace_form", "Coloration:", None))
        self.refresh_button.setToolTip(_translate("trace_form", "Refresh function information of the trace", None))
        self.refresh_button.setText(_translate("trace_form", "Refresh infos", None))
        self.disassemble_button.setToolTip(_translate("trace_form", "disassemble program following the trace (* stop at the first wave *)", None))
        self.disassemble_button.setText(_translate("trace_form", "Disassemble", None))
        self.label_10.setText(_translate("trace_form", "Utils:", None))
        self.colorize_button.setToolTip(_translate("trace_form", "Colorize the trace to vizualize code coverage", None))
        self.colorize_button.setText(_translate("trace_form", "Colorize trace", None))
        self.heatmap_button.setToolTip(_translate("trace_form", "Colorize the code by instruction occurence", None))
        self.heatmap_button.setText(_translate("trace_form", "Heatmap", None))
        self.label_8.setText(_translate("trace_form", "Disassembly:", None))

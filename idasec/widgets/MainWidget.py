# coding: utf8

import time
import sys

from PySide import QtGui, QtCore
from PySide.QtGui import QIntValidator, QPixmap

#from idasec.ui.main import Ui_Main
from idasec.message import MessageInfos, MessageDecodeInstr, MessageDecodeInstrReply
from idasec.dba_printer import instr_to_string
from idasec.utils import *
import idasec.ui.resources_rc
from idasec.commands import *
import re

import idc

class MainWidget(QtGui.QWidget):
    def __init__(self, parent):
        super(MainWidget, self).__init__()
        self.parent = parent
        self.name = "MainWidget"
        self.core = self.parent.core
        self.broker = self.core.broker
        self.icon = QtGui.QIcon("semantics.png")
        self.OnCreate(self)

    # class IDASecApp(PluginForm, Ui_Main):

    def OnCreate(self, form):
        self.setupUi(self)
        self.connect(self.binsec_connect_button, QtCore.SIGNAL("clicked()"), self.connect_binsec)
        self.connect(self.dba_decode_button, QtCore.SIGNAL("clicked()"), self.decode_button_clicked)
        self.connect(self.here_decode_button, QtCore.SIGNAL("clicked()"), self.decode_here_clicked)
        self.idasec_title.mousePressEvent = self.change_logo
        self.connect(self.idasec_title, QtCore.SIGNAL("clicked()"), self.change_logo)

        self.pinsec_ip_field.setText("192.168.56.101")
        self.pinsec_port_field.setText("5555")
        self.binsec_port_field.setValidator(QIntValidator(0, 65535))
        self.pinsec_port_field.setValidator(QIntValidator(0, 65535))
        self.ok = QtGui.QPixmap(":/icons/icons/oxygen/22x22/ok.png")
        self.ko = QtGui.QPixmap(":/icons/icons/oxygen/22x22/ko.png")
        self.prev_modules = sys.modules.keys()

    def connect_binsec(self):
        try:
            time.sleep(0.1)
        except Exception:
            print "Something went wrong (with Binsec connection)..."

        if self.core.binsec_connected:
            self.broker.disconnect_binsec()
            self.set_disconnected()
        else:
            ip = self.binsec_ip_field.text()
            port = self.binsec_port_field.text()
            self.broker.connect_binsec(ip, port)
            self.broker.send_binsec_message("GET_INFOS", "STUB", blocking=False)
            time.sleep(0.1)
            cmd, data = self.broker.receive_binsec_message(blocking=False)
            if cmd is not None and data is not None:
                print "Connected to Binsec"
                self.binsec_label_status.setPixmap(self.ok)
                message = MessageInfos()
                message.parse(data)
                nb_workers, analyses, solvers = message.get_infos()
                self.infos_label.setText(
                    "CPU:%d\nAnalyses:%s\nSolvers:%s" % (nb_workers, " ".join(analyses), " ".join(solvers)))
                self.parent.add_solvers(solvers)
                self.parent.add_analyses([x.upper() for x in analyses])
                self.core.nb_cpus = nb_workers
                self.set_connected()
            else:
                print "Not Connected to Binsec"
                self.set_disconnected()
                self.binsec_label_status.setPixmap(self.ko)

    def set_connected(self):
        self.core.binsec_connected = True
        self.infos_title_label.setEnabled(True)
        self.infos_label.setEnabled(True)
        self.utils_label.setEnabled(True)
        self.ir_label.setEnabled(True)
        self.dba_decode_field.setEnabled(True)
        self.dba_decode_button.setEnabled(True)
        self.ir_textarea.setEnabled(True)
        self.binsec_connect_button.setText("disconnect")
        self.binsec_port_field.setEnabled(False)
        self.binsec_ip_field.setEnabled(False)

    def set_disconnected(self):
        self.core.binsec_connected = False
        self.binsec_label_status.clear()
        self.infos_title_label.setEnabled(False)
        self.infos_label.setEnabled(False)
        self.utils_label.setEnabled(False)
        self.ir_label.setEnabled(False)
        self.dba_decode_field.setEnabled(False)
        self.dba_decode_button.setEnabled(False)
        self.ir_textarea.setEnabled(False)
        self.binsec_connect_button.setText("connect")
        self.binsec_port_field.setEnabled(True)
        self.binsec_ip_field.setEnabled(True)

    def decode_here_clicked(self):
        inst = idc.here()
        if not idc.isCode(idc.GetFlags(inst)):
            print "Not code instruction"
        else:
            raw = idc.GetManyBytes(inst, idc.NextHead(inst)-inst)
            s = to_hex(raw)
        self.decode_ir(s)

    def decode_button_clicked(self):
        opc = self.dba_decode_field.text().encode('ascii', 'ignore').replace(" ","")
        if not re.match('^[0-9a-fA-F]+$', opc):
            print "Invalid input:"+opc
            return
        self.decode_ir(opc)

    def decode_ir(self, opc):
        if not self.core.binsec_connected:
            self.parent.log("ERROR", "Not connected to Binsec")
            return

        if opc != "":
            mess = MessageDecodeInstr(kind="hexa", instrs=opc, base_addrs=0)
            raw = mess.serialize()
            self.broker.send_binsec_message("DECODE_INSTR", raw, blocking=False)
            time.sleep(0.2)
            cmd, data = self.broker.receive_binsec_message(blocking=False)
            if cmd is not None and data is not None:
                if cmd == END:
                    self.ir_textarea.setText("Error occured:"+data)
                elif cmd == DECODE_INSTR_REPLY:
                    reply = MessageDecodeInstrReply()
                    reply.parse(data)
                    for opc, dbainsts in reply.instrs:
                        self.ir_textarea.setText(opc+":")
                        length = len(dbainsts)-1
                        arr = ["⎧" if i==0 else "⎩" if i==length-1 else "⎨" if i==length/2 else "⎪" for i in range(length)]
                        arr = [""] if length == 1 else arr
                        for i in range(len(dbainsts[:-1])):
                            dba = dbainsts[i]
                            self.ir_textarea.append(arr[i]+instr_to_string(dba))
                else:
                    print "Unknown cmd:"+cmd
            else:
                print "Timeout exceeded to receive a binsec reply"
        else:
            print "Invalid input :"+opc

    def OnClose(self, form):
        print("Closed invoked !")
        pass

    def change_logo(self,stub):
        print "clickedd !!!!"
        self.idasec_title.setPixmap(QtGui.QPixmap(":/icons/icons/idasec_small.png"))

    def setupUi(self, Main):
        def _fromUtf8(s):
            return s
        def _translate(x,y,z):
            return y
        Main.setObjectName(_fromUtf8("Main"))
        Main.resize(467, 358)
        Main.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.verticalLayout = QtGui.QVBoxLayout(Main)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.master_layout = QtGui.QVBoxLayout()
        self.master_layout.setObjectName(_fromUtf8("master_layout"))
        self.idasec_title = QtGui.QLabel(Main)
        font = QtGui.QFont()
        font.setPointSize(14)
        font.setBold(True)
        font.setWeight(75)
        self.idasec_title.setFont(font)
        self.idasec_title.setText(_fromUtf8(""))
        self.idasec_title.setPixmap(QtGui.QPixmap(_fromUtf8(":/icons/icons/idasec_small.png")))
        self.idasec_title.setAlignment(QtCore.Qt.AlignCenter)
        self.idasec_title.setObjectName(_fromUtf8("idasec_title"))
        self.master_layout.addWidget(self.idasec_title)
        self.binsec_layout = QtGui.QHBoxLayout()
        self.binsec_layout.setObjectName(_fromUtf8("binsec_layout"))
        self.binsec_label = QtGui.QLabel(Main)
        self.binsec_label.setObjectName(_fromUtf8("binsec_label"))
        self.binsec_layout.addWidget(self.binsec_label)
        self.binsec_ip_field = QtGui.QLineEdit(Main)
        self.binsec_ip_field.setObjectName(_fromUtf8("binsec_ip_field"))
        self.binsec_layout.addWidget(self.binsec_ip_field)
        self.label_3 = QtGui.QLabel(Main)
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.binsec_layout.addWidget(self.label_3)
        self.binsec_port_field = QtGui.QLineEdit(Main)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.binsec_port_field.sizePolicy().hasHeightForWidth())
        self.binsec_port_field.setSizePolicy(sizePolicy)
        self.binsec_port_field.setMaximumSize(QtCore.QSize(100, 16777215))
        self.binsec_port_field.setObjectName(_fromUtf8("binsec_port_field"))
        self.binsec_layout.addWidget(self.binsec_port_field)
        self.binsec_connect_button = QtGui.QPushButton(Main)
        self.binsec_connect_button.setObjectName(_fromUtf8("binsec_connect_button"))
        self.binsec_layout.addWidget(self.binsec_connect_button)
        self.binsec_label_status = QtGui.QLabel(Main)
        self.binsec_label_status.setText(_fromUtf8(""))
        self.binsec_label_status.setObjectName(_fromUtf8("binsec_label_status"))
        self.binsec_layout.addWidget(self.binsec_label_status)
        self.master_layout.addLayout(self.binsec_layout)
        self.pinsec_layout = QtGui.QHBoxLayout()
        self.pinsec_layout.setObjectName(_fromUtf8("pinsec_layout"))
        self.pinsec_label = QtGui.QLabel(Main)
        self.pinsec_label.setObjectName(_fromUtf8("pinsec_label"))
        self.pinsec_layout.addWidget(self.pinsec_label)
        self.pinsec_ip_field = QtGui.QLineEdit(Main)
        self.pinsec_ip_field.setObjectName(_fromUtf8("pinsec_ip_field"))
        self.pinsec_layout.addWidget(self.pinsec_ip_field)
        self.label_2 = QtGui.QLabel(Main)
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.pinsec_layout.addWidget(self.label_2)
        self.pinsec_port_field = QtGui.QLineEdit(Main)
        self.pinsec_port_field.setMaximumSize(QtCore.QSize(100, 16777215))
        self.pinsec_port_field.setObjectName(_fromUtf8("pinsec_port_field"))
        self.pinsec_layout.addWidget(self.pinsec_port_field)
        self.pinsec_connect_button = QtGui.QPushButton(Main)
        self.pinsec_connect_button.setObjectName(_fromUtf8("pinsec_connect_button"))
        self.pinsec_layout.addWidget(self.pinsec_connect_button)
        self.pinsec_label_status = QtGui.QLabel(Main)
        self.pinsec_label_status.setText(_fromUtf8(""))
        self.pinsec_label_status.setObjectName(_fromUtf8("pinsec_label_status"))
        self.pinsec_layout.addWidget(self.pinsec_label_status)
        self.master_layout.addLayout(self.pinsec_layout)
        self.infos_title_label = QtGui.QLabel(Main)
        self.infos_title_label.setEnabled(False)
        self.infos_title_label.setObjectName(_fromUtf8("infos_title_label"))
        self.master_layout.addWidget(self.infos_title_label)
        self.infos_label = QtGui.QLabel(Main)
        self.infos_label.setText(_fromUtf8(""))
        self.infos_label.setObjectName(_fromUtf8("infos_label"))
        self.master_layout.addWidget(self.infos_label)
        self.line = QtGui.QFrame(Main)
        self.line.setFrameShape(QtGui.QFrame.HLine)
        self.line.setFrameShadow(QtGui.QFrame.Sunken)
        self.line.setObjectName(_fromUtf8("line"))
        self.master_layout.addWidget(self.line)
        self.utils_label = QtGui.QLabel(Main)
        self.utils_label.setEnabled(False)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        font.setItalic(False)
        font.setUnderline(True)
        font.setWeight(75)
        self.utils_label.setFont(font)
        self.utils_label.setAlignment(QtCore.Qt.AlignCenter)
        self.utils_label.setObjectName(_fromUtf8("utils_label"))
        self.master_layout.addWidget(self.utils_label)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.ir_label = QtGui.QLabel(Main)
        self.ir_label.setEnabled(False)
        self.ir_label.setObjectName(_fromUtf8("ir_label"))
        self.horizontalLayout.addWidget(self.ir_label)
        self.dba_decode_field = QtGui.QLineEdit(Main)
        self.dba_decode_field.setEnabled(False)
        self.dba_decode_field.setText(_fromUtf8(""))
        self.dba_decode_field.setObjectName(_fromUtf8("dba_decode_field"))
        self.horizontalLayout.addWidget(self.dba_decode_field)
        self.dba_decode_button = QtGui.QPushButton(Main)
        self.dba_decode_button.setEnabled(False)
        self.dba_decode_button.setObjectName(_fromUtf8("dba_decode_button"))
        self.horizontalLayout.addWidget(self.dba_decode_button)
        self.here_decode_button = QtGui.QPushButton(Main)
        self.here_decode_button.setMaximumSize(QtCore.QSize(25, 25))
        self.here_decode_button.setText(_fromUtf8(""))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/icons/icons/open-iconic-master/png/3x/target-3x.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.here_decode_button.setIcon(icon)
        self.here_decode_button.setIconSize(QtCore.QSize(12, 12))
        self.here_decode_button.setObjectName(_fromUtf8("here_decode_button"))
        self.horizontalLayout.addWidget(self.here_decode_button)
        self.master_layout.addLayout(self.horizontalLayout)
        self.ir_textarea = QtGui.QTextEdit(Main)
        self.ir_textarea.setEnabled(False)
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("DejaVu Sans Mono"))
        self.ir_textarea.setFont(font)
        self.ir_textarea.setCursorWidth(1)
        self.ir_textarea.setObjectName(_fromUtf8("ir_textarea"))
        self.master_layout.addWidget(self.ir_textarea)
        self.verticalLayout.addLayout(self.master_layout)
        QtCore.QObject.connect(self.dba_decode_button, QtCore.SIGNAL(_fromUtf8("clicked()")), self.ir_textarea.clear)
        QtCore.QMetaObject.connectSlotsByName(Main)
        Main.setWindowTitle(_translate("Main", "IDASec", None))
        self.binsec_label.setText(_translate("Main", "Binsec IP:", None))
        self.binsec_ip_field.setText(_translate("Main", "127.0.0.1", None))
        self.label_3.setText(_translate("Main", "Port:", None))
        self.binsec_port_field.setText(_translate("Main", "5570", None))
        self.binsec_connect_button.setText(_translate("Main", "Connect", None))
        self.pinsec_label.setText(_translate("Main", "Pinsec IP:", None))
        self.label_2.setText(_translate("Main", "Port:", None))
        self.pinsec_connect_button.setText(_translate("Main", "Connect", None))
        self.infos_title_label.setText(_translate("Main", "Infos:", None))
        self.utils_label.setText(_translate("Main", "Utils", None))
        self.ir_label.setText(_translate("Main", "IR Decode:", None))
        self.dba_decode_field.setToolTip(_translate("Main", "Instruction Hex eg:85db", None))
        self.dba_decode_button.setText(_translate("Main", "Decode", None))
# coding: utf8

import time
import sys
import re

from PyQt5 import QtGui, QtWidgets
import idc

from idasec.ui.main_ui import Ui_Main
from idasec.message import MessageInfos, MessageDecodeInstr, MessageDecodeInstrReply
from idasec.dba_printer import instr_to_string
from idasec.utils import to_hex
from idasec.commands import END, DECODE_INSTR_REPLY



class MainWidget(QtWidgets.QWidget, Ui_Main):
    def __init__(self, parent):
        super(MainWidget, self).__init__()
        self.parent = parent
        self.name = "MainWidget"
        self.core = self.parent.core
        self.broker = self.core.broker
        self.icon = QtGui.QIcon("semantics.png")
        self.OnCreate(self)

    # class IDASecApp(PluginForm, Ui_Main):

    def OnCreate(self, _):
        self.setupUi(self)
        self.binsec_connect_button.clicked.connect(self.connect_binsec)
        self.dba_decode_button.clicked.connect(self.decode_button_clicked)
        self.here_decode_button.clicked.connect(self.decode_here_clicked)
        self.pinsec_ip_field.setText("192.168.56.101")
        self.pinsec_port_field.setText("5555")
        self.binsec_port_field.setValidator(QtGui.QIntValidator(0, 65535))
        self.pinsec_port_field.setValidator(QtGui.QIntValidator(0, 65535))
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
        opc = self.dba_decode_field.text().encode('ascii', 'ignore').replace(" ", "")
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
                        arr = ["⎧" if i == 0 else "⎩" if i == length - 1 else "⎨" if i == length / 2 else "⎪"
                               for i in range(length)]
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

    def OnClose(self, _):
        print("Closed invoked !")
        pass

#!/usr/bin/env python
# coding: utf-8
########################################################################
# Copyright (c) 2016
# Author: Robin David <robin.david<at>cea<dot>com>
# CEA (Commissariat à l'énergie atomique et aux énergies alternatives)
# All rights reserved.
########################################################################
#
#  This file is part of IDASec
#
#  IDAsec is free software: you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation, version 2.1
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see
#  <http://www.gnu.org/licenses/>.
#
########################################################################
import sys
import time
import datetime

from PySide import QtGui, QtCore

import ctypes
from idasec.widgets.MainWidget import MainWidget
from idasec.widgets.TraceWidget import TraceWidget
from idasec.idasec_core import IDASecCore
from idasec.widgets.AnalysisWidget import AnalysisWidget
from idasec.path import Path
from idasec.analysis.default_analysis import DefaultAnalysis
from idasec.analysis.generic_analysis import GenericAnalysis
from idasec.analysis.callret_analysis import CallRetAnalysis
from idasec.analysis.opaque_analysis import OpaqueAnalysis
from idasec.analysis.static_opaque_analysis import StaticOpaqueAnalysis


IDA_ENABLED = False
try:
    import idaapi
    from idaapi import PluginForm, plugin_t
    IDA_ENABLED = True
except ImportError:
    class PluginForm:
        def __init__(self):
            pass
    class plugin_t:
        def __init__(self):
            pass
    class idaapi:
        PLUGIN_UNL=None
        PLUGIN_OK=None
        def __init__(self):
            pass
    IDA_ENABLED = False


IDASEC = None
NAME = "IDASec"



class IDASecForm(PluginForm):
    def __init__(self):
        super(IDASecForm, self).__init__()
        global HOTKEYS
        HOTKEYS = []

    def OnCreate(self, form):
        # Internal data structures
        self.running_analyses = {}
        self.core = IDASecCore()
        self.parent = self.FormToPySideWidget(form)
        self.setupUi(self.parent)
        self.main_widget = MainWidget(self)
        self.trace_widget = TraceWidget(self)
        self.analysis_widget = AnalysisWidget(self)
        #---------------------------------

        # -- ui stuff
        self.tab_widget.setTabsClosable(True)
        self.parent.connect(self.tab_widget, QtCore.SIGNAL('tabCloseRequested(int)'), self.close_tab_action)
        self.tab_widget.addTab(self.main_widget, "Main")
        self.tab_widget.addTab(self.trace_widget, "Trace")
        self.tab_widget.addTab(self.analysis_widget, "Analysis")
        self.tab_widget.tabBar().tabButton(0, self.tab_widget.tabBar().RightSide).hide()
        self.tab_widget.tabBar().tabButton(1, self.tab_widget.tabBar().RightSide).hide()
        self.tab_widget.tabBar().tabButton(2, self.tab_widget.tabBar().RightSide).hide()

    def OnClose(self, form):
        global IDASEC
        try:
            del IDASEC
        except NameError:
            print "IDASec apparently already deleted !"

    def setTabFocus(self, name):
        widget = {"Main":self.main_widget, "Trace":self.trace_widget, "Analysis":self.analysis_widget}[name]
        index = self.tab_widget.indexOf(widget)
        self.tab_widget.setCurrentIndex(index)

    def close_tab_action(self, i):
        idx = id(self.tab_widget.widget(i))
        analyse = self.running_analyses[idx]
        analyse.stop()
        self.tab_widget.removeTab(i)
        self.running_analyses.pop(idx)

    def start_analysis(self, name, conf, is_stream=False, trace=None):
        binsec_ip, binsec_port = self.main_widget.binsec_ip_field.text(), self.main_widget.binsec_port_field.text()
        pinsec_ip, pinsec_port = self.main_widget.pinsec_ip_field.text(), self.main_widget.pinsec_port_field.text()

        if binsec_ip == "" or binsec_port == "":
            print "No IP or port specified for Binsec"
        elif is_stream and (pinsec_ip == "" or pinsec_port == ""):
            print "No IP or port specified for Pinsec"
        else:
            analysis = self.analysis_from_name(name)(self, conf, is_stream, trace)
            index = self.tab_widget.addTab(analysis.result_widget, name.capitalize())
            self.tab_widget.setCurrentIndex(index)
            self.running_analyses[id(analysis.result_widget)] = analysis

            analysis.broker.connect_binsec(binsec_ip, binsec_port)
            if is_stream:
                analysis.broker.connect_pinsec(pinsec_ip, pinsec_port)
            analysis.run()

    def get_current_analysis(self):
        widget = self.tab_widget.widget(self.tab_widget.currentIndex())
        return self.running_analyses[id(widget)]

    def analysis_from_name(self, name):
        name = name.upper()
        if name == "GENERIC":
            return GenericAnalysis
        elif name == "CALLRET":
            return CallRetAnalysis
        elif name == "OPAQUE":
            return OpaqueAnalysis
        elif name == "STATIC OPAQUE":
            return StaticOpaqueAnalysis
        else:
            return DefaultAnalysis


    def Show(self):
        return PluginForm.Show(self,
                NAME,
                options=(PluginForm.FORM_CLOSE_LATER | PluginForm.FORM_RESTORE | PluginForm.FORM_SAVE))

    def add_trace(self, t):
        index = self.core.add_trace(t)
        self.analysis_widget.trace_selector.addItem("#%d %s" % (index, Path(t.filename).name))
        return index

    def add_solvers(self, solvers):
        for s in solvers:
            self.analysis_widget.solver_selector.addItem(s)
        self.core.solvers = solvers

    def add_analyses(self, analyses):
        self.analysis_widget.analysis_name_selector.clear()
        for a in analyses:
            self.analysis_widget.analysis_name_selector.addItem(a)
        self.core.analyses = analyses
        self.add_internal_analyses(analyses)

    def add_internal_analyses(self, dyn_analyses):
        if "OPAQUE" in dyn_analyses:
            self.analysis_widget.analysis_name_selector.addItem("STATIC OPAQUE")
            self.core.analyses.append("STATIC OPAQUE")

    def remove_trace(self, tr_id):
        tr = self.core.traces[tr_id]
        index = self.analysis_widget.trace_selector.findText("#%d %s" % (tr_id, Path(tr.filename).name))
        self.analysis_widget.trace_selector.removeItem(index)
        self.core.remove_trace(tr_id)

    def setupUi(self, Master):
        Master.setObjectName("Master")
        Master.resize(718, 477)
        self.verticalLayout = QtGui.QVBoxLayout(Master)
        self.verticalLayout.setObjectName("verticalLayout")
        self.splitter = QtGui.QSplitter(Master)
        self.splitter.setOrientation(QtCore.Qt.Vertical)
        self.splitter.setObjectName("splitter")
        self.tab_widget = QtGui.QTabWidget(self.splitter)
        self.tab_widget.setObjectName("tab_widget")

        self.docker = QtGui.QDockWidget(self.splitter)
        self.docker.setObjectName("docker")
        self.docker.setAllowedAreas(QtCore.Qt.BottomDockWidgetArea)

        self.log_widget = QtGui.QTreeWidget(self.docker)
        self.log_widget.setHeaderItem(QtGui.QTreeWidgetItem(["date", "origin", "type", "message"]))
        self.docker.setWidget(self.log_widget)

        self.verticalLayout.addWidget(self.splitter)
        self.tab_widget.setCurrentIndex(-1)
        QtCore.QMetaObject.connectSlotsByName(Master)
        Master.setWindowTitle("IDASec")

    def log(self,type, message, origin="IDASec"):
        date = datetime.datetime.now().strftime("%H:%M:%S")
        res = re.match("^(\[[A-Za-z]*\])",message)
        if res:
            type = res.groups()[0]
            message = message[len(type):].lstrip()
        message = message.rstrip()
        self.log_widget.addTopLevelItem(QtGui.QTreeWidgetItem([date, origin, type, message]))
        self.log_widget.scrollToBottom()


################################################################################
# Usage as plugin
################################################################################
def PLUGIN_ENTRY():
    return IDASecPlugin()

class IDASecPlugin(plugin_t):

    flags = idaapi.PLUGIN_UNL
    comment = NAME
    help = "IDASec - IDA Interface for the Binsec platform"
    wanted_name = "IDASec"
    wanted_hotkey = "Ctrl-F1"

    def init(self):
        self.icon_id = 0
        return idaapi.PLUGIN_OK

    def run(self, arg=0):
        print "Run IDASec"
        f = IDASecForm()
        f.Show()
        return

    def term(self):
        pass


class IDASecStandalone:
    def __init__(self):
        self.core = IDASecCore()
        self.traces = []

    def remove_trace(self,tr_id):
        print "remove trace %d" % tr_id

    def add_trace(self, tr):
        print "Add trace"

################################################################################
# Usage as script
################################################################################
def main():
    idaapi.msg("Loading IDASEC\n")
    global IDASEC
    try:
        IDASEC
        IDASEC.OnClose(IDASEC)
        idaapi.msg("reloading IDASec\n")
        IDASEC = IDASecForm()
        return
    except Exception:
        IDASEC = IDASecForm()
    IDASEC.Show()


def main_standalone():
    app = QtGui.QApplication(sys.argv)
    ida_app = IDASecStandalone()
    form = AnalysisWidget(ida_app)
    form.show()
    app.exec_()

if __name__ == "__main__":
    if IDA_ENABLED:
        main()
    else:
        main_standalone()

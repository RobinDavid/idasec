from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QWidget
from idasec.proto.analysis_config_pb2 import standard_analysis, specific_parameters_t
import idasec.utils as utils

import idc
import idasec.ui.resources_rc

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

class StandardParamConfigWidget(QWidget):

    def __init__(self):
        super(StandardParamConfigWidget, self).__init__()
        self.conf = standard_analysis()
        self.setupUi(self)
        self.target_button.clicked.connect(self.target_button_clicked)

    def set_fields(self, json_fields):
        gen = json_fields["standard_params"]
        if gen.has_key("target_addr"):
            self.target_field.setText(hex(gen["target_addr"]))
        if gen.has_key("uniq"):
            self.uniq_checkbox.setChecked(gen["uniq"])

    def serialize(self):
        target_addr = self.target_field.text()
        try:
            if target_addr != "":
                self.conf.target_addr = utils.to_addr(target_addr)
        except ValueError:
            print "Invalid values for target address"

        #if self.uniq_checkbox.isChecked():
        self.conf.uniq = self.uniq_checkbox.isChecked()

        try:
            params = specific_parameters_t()
            params.typeid = params.STANDARD
            params.standard_params.CopyFrom(self.conf)
            return params
        except:
            print "Analysis specific arguments serialization failed"
            return None

    def target_button_clicked(self):
        self.target_field.setText(hex(idc.here()))

    def setupUi(self, standard_params):
        def _fromUtf8(s):
            return s
        def _translate(x,y,z):
            return y
        standard_params.setObjectName(_fromUtf8("standard_params"))
        standard_params.resize(293, 82)
        self.verticalLayout = QtWidgets.QVBoxLayout(standard_params)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.target_label = QtWidgets.QLabel(standard_params)
        self.target_label.setObjectName(_fromUtf8("target_label"))
        self.horizontalLayout.addWidget(self.target_label)
        self.target_field = QtWidgets.QLineEdit(standard_params)
        self.target_field.setObjectName(_fromUtf8("target_field"))
        self.horizontalLayout.addWidget(self.target_field)
        self.target_button = QtWidgets.QPushButton(standard_params)
        self.target_button.setMaximumSize(QtCore.QSize(25, 25))
        self.target_button.setText(_fromUtf8(""))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/icons/icons/open-iconic-master/png/3x/target-3x.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.target_button.setIcon(icon)
        self.target_button.setObjectName(_fromUtf8("target_button"))
        self.horizontalLayout.addWidget(self.target_button)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.uniq_checkbox = QtWidgets.QCheckBox(standard_params)
        self.uniq_checkbox.setObjectName(_fromUtf8("uniq_checkbox"))
        self.horizontalLayout_2.addWidget(self.uniq_checkbox)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        QtCore.QMetaObject.connectSlotsByName(standard_params)
        standard_params.setWindowTitle(_translate("standard_params", "Form", None))
        self.target_label.setText(_translate("standard_params", "Target:", None))
        self.uniq_checkbox.setText(_translate("standard_params", "Unique results (per target)", None))

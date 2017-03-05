from PyQt5 import QtWidgets
from idasec.proto.analysis_config_pb2 import standard_analysis, specific_parameters_t
import idasec.utils as utils
from idasec.ui.standard_params_ui import Ui_standard_params

import idc
import idasec.ui.resources_rc

class StandardParamConfigWidget(QtWidgets.QWidget, Ui_standard_params):

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

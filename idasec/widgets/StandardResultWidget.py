from PyQt5 import QtWidgets

from idasec.ui.standard_result_ui import Ui_standard_result


class StandardResultWidget(QtWidgets.QWidget, Ui_standard_result):

    def __init__(self, parent):
        QtWidgets.QWidget.__init__(self)
        self.setupUi(self)
        self.parent = parent
        self.action_selector.setEnabled(False)
        self.action_button.setEnabled(False)
        for k in self.parent.actions.keys():

            self.action_selector.addItem(k)
        self.action_button.clicked.connect(self.action_clicked)
        self.action_selector.currentIndexChanged[str].connect(self.action_selector_changed)

    def action_selector_changed(self, s):
        _, enabled = self.parent.actions[s]
        if enabled:
            self.action_button.setText("Undo !")
        else:
            self.action_button.setText("Do !")

    def action_clicked(self):
        s = self.action_selector.currentText()
        fun, enabled = self.parent.actions[s]
        fun(enabled)

    def set_actions_visible_and_enabled(self, enable):
        self.action_label.setVisible(enable)
        self.action_selector.setVisible(enable)
        self.action_button.setVisible(enable)
        self.action_selector.setEnabled(enable)
        self.action_button.setEnabled(enable)

from PyQt5 import QtGui, QtCore, QtWidgets


class ButtonLineEdit(QtWidgets.QLineEdit):

    def __init__(self, items, parent=None):
        super(ButtonLineEdit, self).__init__(parent)

        self.menu = QtWidgets.QMenu()
        for i in items:
          self.menu.addAction(i)

        self.button = QtWidgets.QToolButton(self)
        self.button.setStyleSheet('border: 0px; padding: 0px;')
        self.button.setCursor(QtCore.Qt.ArrowCursor)
        self.button.triggered.connect(self.menu_action_triggered)
        self.button.setPopupMode(QtWidgets.QToolButton.InstantPopup)
        self.button.setMenu(self.menu)

        frameWidth = self.style().pixelMetric(QtWidgets.QStyle.PM_DefaultFrameWidth)
        buttonSize = self.button.sizeHint()

        self.setAlignment(QtCore.Qt.Alignment(QtCore.Qt.AlignHCenter))
        self.setStyleSheet('QLineEdit {padding-right: %dpx; }' % (buttonSize.width() + frameWidth + 1))
        self.setMinimumSize(max(self.minimumSizeHint().width(), buttonSize.width() + frameWidth*2 + 2),
                            max(self.minimumSizeHint().height(), buttonSize.height() + frameWidth*2 + 2))
        self.setMaximumWidth(100)

    def resizeEvent(self, event):
        buttonSize = self.button.sizeHint()
        frameWidth = self.style().pixelMetric(QtWidgets.QStyle.PM_DefaultFrameWidth)
        self.button.move(self.rect().right() - frameWidth - buttonSize.width(),
                         (self.rect().bottom() - buttonSize.height() + 1)/2)
        super(ButtonLineEdit, self).resizeEvent(event)

    def menu_action_triggered(self, action):
      self.setText(action.text())

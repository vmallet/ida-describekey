# SPDX-FileCopyrightText: 2022 Vincent Mallet <vmallet@gmail.com>
# SPDX-License-Identifier: MIT

"""
DescribeKey: a simple action to display actions associated with a
shortcut, live.
"""

from collections import defaultdict
from typing import Tuple, Dict, Any

from PyQt5 import QtWidgets, QtCore
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QKeyEvent, QKeySequence, QResizeEvent
from PyQt5.QtWidgets import QDialog, QTableWidget, QTableWidgetSelectionRange, \
    QVBoxLayout, QHeaderView, QLabel, QHBoxLayout

import ida_kernwin

__author__ = "https://github.com/vmallet"

# TODO: use some sort of built-in window/dialog and have iDA remember last position

# Column indices for action table
COL_LABEL = 0
COL_ACTION = 1
COL_SHORTCUT = 2
COL_TOOLTIP = 3
COL_STATE = 4
COL_VISIBILITY = 5
COL_CHECKABLE = 6
COL_CHECKED = 7
COLUMN_COUNT = 8


class KeyNamer(object):
    """
    Provide a mean to get an IDA-compatible shortcut representation of
    a key event.

    See keyevent_to_shortcut()
    """

    def __init__(self):
        self._keymap, self._modmap = self._init_key_names()

    def _init_key_names(self) -> Tuple[Dict[int, str], Dict[Any, str]]:
        """Init the key tables necessary to identify shortcuts"""
        keymap = dict()
        for key, value in vars(Qt).items():
            if isinstance(value, Qt.Key):
                # print("key: {}   value: {:X}".format(key, value))
                keymap[value] = key.partition('_')[2]

        modmap = {
            Qt.ControlModifier: "Ctrl",
            Qt.AltModifier: "Alt",
            Qt.ShiftModifier: "Shift",
            Qt.MetaModifier: "Meta",
            Qt.GroupSwitchModifier: keymap[Qt.Key_AltGr],
            Qt.KeypadModifier: keymap[Qt.Key_NumLock],
            }

        return keymap, modmap

    def keyevent_to_shortcut(self, event):

        key = self._keymap.get(event.nativeVirtualKey(), None) \
              or self._keymap.get(event.key(), event.text())
        if not key:
            return None
        sequence = []
        for modifier, text in self._modmap.items():
            if event.modifiers() & modifier:
                sequence.append(text)
        if key not in sequence:
            sequence.append(key)
        return '-'.join(sequence)


class ActionInfo(object):
    """Description of a registered action."""

    def __init__(self, label, action, shortcut, tooltip, state, visibility, checkable, checked):
        self.label = label
        self.action = action
        self.shortcut = shortcut
        self.tooltip = tooltip
        self.state = state
        self.visibility = visibility
        self.checkable = checkable
        self.checked = checked

    @classmethod
    def for_action(cls, action):
        """Construct an ActionInfo for the given action name."""

        def unw(ret):
            return ret[1] if ret and ret[0] else None

        shortcut = ida_kernwin.get_action_shortcut(action)
        label = ida_kernwin.get_action_label(action)
        tooltip = ida_kernwin.get_action_tooltip(action)
        state = unw(ida_kernwin.get_action_state(action))
        visibility = unw(ida_kernwin.get_action_visibility(action))
        checkable = unw(ida_kernwin.get_action_checkable(action))
        checked = unw(ida_kernwin.get_action_checked(action))

        return ActionInfo(label, action, shortcut, tooltip, state, visibility, checkable,
                          checked)


class DescribeKey(object):
    #TODO: docstring

    def __init__(self):
        self._namer = KeyNamer()
        self._astmap = self._build_ast_map()
        self._shortcut_label = QLabel("Press a shortcut...")
        self._table = self._build_table()
        self._dialog = self._build_dialog()

    def _build_ast_map(self):
        astmap = {
            ida_kernwin.AST_ENABLE: "Enable",
            ida_kernwin.AST_ENABLE_ALWAYS: "Enable Always",
            ida_kernwin.AST_ENABLE_FOR_WIDGET: "Enable for Widget",
            ida_kernwin.AST_ENABLE_FOR_IDB: "Enable for IDB",
            ida_kernwin.AST_DISABLE: "Disable",
            ida_kernwin.AST_DISABLE_ALWAYS: "Disable Always",
            ida_kernwin.AST_DISABLE_FOR_WIDGET: "Disable for Widget",
            ida_kernwin.AST_DISABLE_FOR_IDB: "Disable for IDB",
        }
        return astmap

    def _build_action_map(self):
        action_map = defaultdict(list)

        actions = ida_kernwin.get_registered_actions()
        for name in actions:
            shortcut = ida_kernwin.get_action_shortcut(name)
            if shortcut:
                action_map[shortcut].append(name)

        return action_map

    def _handle_keyevent(self, event: QKeyEvent, action_map, fn):
        shortcut = self._namer.keyevent_to_shortcut(event)
        # TODO: remove debug
        print("evt: {}  {:X}  {}  {}  {:x}  {:x}".format(event, event.key(), event.text(), shortcut,
                                                         event.nativeVirtualKey(), event.nativeScanCode()))

        self._set_shortcut(shortcut)

        actions = action_map.get(shortcut, []) if shortcut else []
        self._set_data(actions)

        # Only the ESC key goes through
        if event.matches(QKeySequence.Cancel):
            fn(event)

    def _build_table(self) -> QTableWidget:
        table = QtWidgets.QTableWidget()
        table.setColumnCount(COLUMN_COUNT)
        table.setRowCount(0)

        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

        table.setHorizontalHeaderItem(COL_LABEL, QtWidgets.QTableWidgetItem("Label"))
        table.setHorizontalHeaderItem(COL_ACTION, QtWidgets.QTableWidgetItem("Action"))
        table.setHorizontalHeaderItem(COL_SHORTCUT, QtWidgets.QTableWidgetItem("Shortcut"))
        table.setHorizontalHeaderItem(COL_TOOLTIP, QtWidgets.QTableWidgetItem("Description"))
        table.setHorizontalHeaderItem(COL_STATE, QtWidgets.QTableWidgetItem("State"))
        table.setHorizontalHeaderItem(COL_VISIBILITY, QtWidgets.QTableWidgetItem("V"))
        table.setHorizontalHeaderItem(COL_CHECKABLE, QtWidgets.QTableWidgetItem("C"))
        table.setHorizontalHeaderItem(COL_CHECKED, QtWidgets.QTableWidgetItem("Cd"))

        # Magic calculation in attempt to size the State column more or less sensibly
        state_width = int(table.fontMetrics().width("Disable for Widget") * 1.2) + 5

        table.setColumnWidth(COL_SHORTCUT, 88)
        table.setColumnWidth(COL_STATE, state_width)
        table.setColumnWidth(COL_VISIBILITY, 25)
        table.setColumnWidth(COL_CHECKABLE, 25)
        table.setColumnWidth(COL_CHECKED, 25)

        for i in range(COLUMN_COUNT):
            table.horizontalHeaderItem(i).setTextAlignment(QtCore.Qt.AlignLeft)

        table.verticalHeader().setHidden(True)
        # table.resizeRowToContents()
        table.verticalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        table.verticalHeader().setMaximumSectionSize(19)   # TODO: '19' magic constant

        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        table.horizontalHeader().setStretchLastSection(False)
        table.horizontalHeader().setSectionResizeMode(COL_TOOLTIP, QHeaderView.Stretch)

        table.setShowGrid(False)
        # table.cellDoubleClicked.connect(self._cell_activated)
        # table.cellActivated.connect(self._cell_activated)
        table.setRangeSelected(QTableWidgetSelectionRange(0, 0, 0, 0), True)

        action_map = self._build_action_map()
        old_fn = table.keyPressEvent
        table.keyPressEvent = lambda a: self._handle_keyevent(a, action_map, old_fn)

        old_resize = table.resizeEvent
        def resizeEvent(evt: QResizeEvent):
            """Size LABEL and ACTION columns proportionally to table width"""
            width = evt.size().width()
            if width != evt.oldSize().width():
                self._table.setColumnWidth(COL_LABEL, width / 5)
                self._table.setColumnWidth(COL_ACTION, width / 5)
            old_resize(evt)

        table.resizeEvent = resizeEvent

        return table

    def _set_shortcut(self, shortcut):
        self._shortcut_label.setText(shortcut)

    def _set_data(self, actions):
        self._table.clearContents()
        self._table.setRowCount(len(actions))

        for i, action in enumerate(actions):
            info = ActionInfo.for_action(action)

            # Label
            item = QtWidgets.QTableWidgetItem()
            item.setData(QtCore.Qt.DisplayRole, info.label)
            self._table.setItem(i, COL_LABEL, item)

            # Action
            item = QtWidgets.QTableWidgetItem()
            item.setData(QtCore.Qt.DisplayRole, info.action)
            self._table.setItem(i, COL_ACTION, item)

            # Shortcut
            item = QtWidgets.QTableWidgetItem()
            item.setData(QtCore.Qt.DisplayRole, info.shortcut)
            self._table.setItem(i, COL_SHORTCUT, item)

            # Tooltip
            item = QtWidgets.QTableWidgetItem()
            item.setData(QtCore.Qt.DisplayRole, info.tooltip)
            self._table.setItem(i, COL_TOOLTIP, item)

            # State
            item = QtWidgets.QTableWidgetItem()
            item.setData(QtCore.Qt.DisplayRole,
                         self._astmap.get(info.state, None) or str(info.state))
            self._table.setItem(i, COL_STATE, item)

            # Visibility
            item = QtWidgets.QTableWidgetItem()
            item.setData(QtCore.Qt.DisplayRole, "V" if info.visibility else "")
            self._table.setItem(i, COL_VISIBILITY, item)

            # Checkable
            item = QtWidgets.QTableWidgetItem()
            item.setData(QtCore.Qt.DisplayRole, "Y" if info.checkable else "")
            self._table.setItem(i, COL_CHECKABLE, item)

            # Checked
            item = QtWidgets.QTableWidgetItem()
            item.setData(QtCore.Qt.DisplayRole, "Y" if info.checked else "")
            self._table.setItem(i, COL_CHECKED, item)

    def _build_status(self):
        layout = QHBoxLayout()
        layout.addWidget(QLabel("Shortcut: "))
        layout.addWidget(self._shortcut_label)
        layout.addStretch()
        layout.setContentsMargins(5, 5, 5, 5)
        return layout

    def _build_dialog(self):
        dialog = QDialog()
        dialog.setWindowTitle("Describe Key")
        dialog.resize(800, 200)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._table)
        layout.addLayout(self._build_status())
        dialog.setLayout(layout)

        return dialog

    def show(self):
        dialog = self._build_dialog()
        dialog.exec()


class KeyActionHandler(ida_kernwin.action_handler_t):

    def activate(self, ctx):
        dk = DescribeKey()
        dk.show()
        return False

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

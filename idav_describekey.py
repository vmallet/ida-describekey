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
from PyQt5.QtGui import QKeyEvent, QKeySequence
from PyQt5.QtWidgets import QDialog, QTableWidget, QTableWidgetSelectionRange, QVBoxLayout, \
    QHeaderView

import ida_kernwin

__author__ = "https://github.com/vmallet"


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
        self._table = self._build_table()
        self._dialog = self._build_dialog()

    def _build_ast_map(self):
        astmap = {
            ida_kernwin.AST_ENABLE: "AST_ENABLE",
            ida_kernwin.AST_ENABLE_ALWAYS: "AST_ENABLE_ALWAYS",
            ida_kernwin.AST_ENABLE_FOR_WIDGET: "AST_ENABLE_FOR_WIDGET",
            ida_kernwin.AST_ENABLE_FOR_IDB: "AST_ENABLE_FOR_IDB",
            ida_kernwin.AST_DISABLE: "AST_DISABLE",
            ida_kernwin.AST_DISABLE_ALWAYS: "AST_DISABLE_ALWAYS",
            ida_kernwin.AST_DISABLE_FOR_WIDGET: "AST_DISABLE_FOR_WIDGET",
            ida_kernwin.AST_DISABLE_FOR_IDB: "AST_DISABLE_FOR_IDB",
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

        actions = action_map.get(shortcut, None) if shortcut else None
        if actions:
            self._set_data(actions)

        # Only the ESC key go through
        if event.matches(QKeySequence.Cancel):
            fn(event)

    def _build_table(self) -> QTableWidget:
        table = QtWidgets.QTableWidget()
        table.setColumnCount(8)
        # print("len: {}".format(len(refs)))
        table.setRowCount(0)

        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

        table.setHorizontalHeaderItem(0, QtWidgets.QTableWidgetItem("Label"))
        table.setHorizontalHeaderItem(1, QtWidgets.QTableWidgetItem("Action"))
        table.setHorizontalHeaderItem(2, QtWidgets.QTableWidgetItem("Shortcut"))
        table.setHorizontalHeaderItem(3, QtWidgets.QTableWidgetItem("Description"))
        table.setHorizontalHeaderItem(4, QtWidgets.QTableWidgetItem("State"))
        table.setHorizontalHeaderItem(5, QtWidgets.QTableWidgetItem("V"))
        table.setHorizontalHeaderItem(6, QtWidgets.QTableWidgetItem("C"))
        table.setHorizontalHeaderItem(7, QtWidgets.QTableWidgetItem("Cd"))

        table.setColumnWidth(5, 25)
        table.setColumnWidth(6, 25)
        table.setColumnWidth(7, 25)

        for i in range(8):
            table.horizontalHeaderItem(i).setTextAlignment(QtCore.Qt.AlignLeft)

        table.verticalHeader().setHidden(True)
        # table.resizeRowToContents()
        table.verticalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        table.verticalHeader().setMaximumSectionSize(19)   # TODO: '19' magic constant

        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        table.horizontalHeader().setStretchLastSection(False)
        table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)


        table.setShowGrid(False)
        # table.cellDoubleClicked.connect(self._cell_activated)
        # table.cellActivated.connect(self._cell_activated)
        table.setRangeSelected(QTableWidgetSelectionRange(0, 0, 0, 0), True)

        action_map = self._build_action_map()
        old_fn = table.keyPressEvent
        table.keyPressEvent = lambda a: self._handle_keyevent(a, action_map, old_fn)

        return table

    def _set_data(self, actions):
        self._table.clearContents()
        self._table.setRowCount(len(actions))

        for i, action in enumerate(actions):
            info = ActionInfo.for_action(action)

            # Label
            item = QtWidgets.QTableWidgetItem()
            item.setData(QtCore.Qt.DisplayRole, info.label)
            self._table.setItem(i, 0, item)

            # Action
            item = QtWidgets.QTableWidgetItem()
            item.setData(QtCore.Qt.DisplayRole, info.action)
            self._table.setItem(i, 1, item)

            # Shortcut
            item = QtWidgets.QTableWidgetItem()
            item.setData(QtCore.Qt.DisplayRole, info.shortcut)
            self._table.setItem(i, 2, item)

            # Tooltip
            item = QtWidgets.QTableWidgetItem()
            item.setData(QtCore.Qt.DisplayRole, info.tooltip)
            self._table.setItem(i, 3, item)

            # State
            item = QtWidgets.QTableWidgetItem()
            item.setData(QtCore.Qt.DisplayRole,
                         self._astmap.get(info.state, None) or str(info.state))
            self._table.setItem(i, 4, item)

            # Visibility
            item = QtWidgets.QTableWidgetItem()
            item.setData(QtCore.Qt.DisplayRole, "V" if info.visibility else "")
            self._table.setItem(i, 5, item)

            # Checkable
            item = QtWidgets.QTableWidgetItem()
            item.setData(QtCore.Qt.DisplayRole, "Y" if info.checkable else "")
            self._table.setItem(i, 6, item)

            # Checked
            item = QtWidgets.QTableWidgetItem()
            item.setData(QtCore.Qt.DisplayRole, "Y" if info.checked else "")
            self._table.setItem(i, 7, item)

    def _build_dialog(self):
        dialog = QDialog()
        dialog.setWindowTitle("Key Attempt 2")
        dialog.setMinimumSize(300, 200)
        dialog.resize(700, 500)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._table)
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

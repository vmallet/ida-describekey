# SPDX-FileCopyrightText: 2022 Vincent Mallet <vmallet@gmail.com>
# SPDX-License-Identifier: MIT

"""
DescribeKey: a simple action to display actions associated with a
shortcut, live.
"""

from collections import defaultdict
from typing import Optional

from PyQt5 import QtWidgets, QtCore
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QKeyEvent, QKeySequence, QResizeEvent
from PyQt5.QtWidgets import QDialog, QTableWidget, QTableWidgetSelectionRange, \
    QVBoxLayout, QHeaderView, QLabel, QHBoxLayout

import ida_idaapi
import ida_kernwin
import idaapi

__author__ = "https://github.com/vmallet"

# TODO: use some sort of built-in window/dialog and have iDA remember last position
# TODO: seems to be having issues with ". ; : / - = <arrow-keys>" keys..˚

VERSION = 0.1

DESCRIBE_KEY_ACTION = "DescribeKey"
DESCRIBE_KEY_TEXT = "Describe Key"
DESCRIBE_KEY_SHORTCUT = "Alt-Shift-K"
DESCRIBE_KEY_TOOLTIP = "List all actions associated with a shortcut"

DEBUG = True

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

DIRECT_KEYS = r",./<>?;':\"[]{}()`~!@#$%^&*-_=+"
"""Keys that shouldn't be mapped to a Qt::Key."""


class KeyNamer(object):
    """
    Provide a means to get an IDA-compatible shortcut representation of
    a key event.

    See keyevent_to_shortcut()
    """

    def __init__(self):
        # Key names
        self._keymap = dict()
        for key, value in vars(Qt).items():
            if isinstance(value, Qt.Key):
                self._keymap[value] = key.partition('_')[2]

        # Modifier names. Note: insertion order matters, should match IDA's modifier order
        self._modmap = {
            Qt.ControlModifier: "Ctrl",
            Qt.AltModifier: "Alt",
            Qt.ShiftModifier: "Shift",
            Qt.MetaModifier: "Meta",
            Qt.GroupSwitchModifier: self._keymap[Qt.Key_AltGr],
            Qt.KeypadModifier: self._keymap[Qt.Key_NumLock],
        }

    def keyevent_to_shortcut(self, event) -> Optional[str]:
        """Attempt to produce IDA-compatible shortcut for keyevent."""
        text = event.text()
        if text and text in DIRECT_KEYS:
            key = text
        else:
            # Try to map the key, first using the native virtual key and only
            # if it's a legit key like "A" or "F1", not "guillemotleft" or "cent"
            native = self._keymap.get(event.nativeVirtualKey(), None)
            if native and len(native) > 2:
                native = None
            # If we don't have a simple key, try to map the actual event key and
            # if all else fails, use the event text
            key = native or self._keymap.get(event.key(), text)

        if key in [None, "Control", "Alt", "Shift", "Meta"]:
            return None

        if event.modifiers() == Qt.ShiftModifier and key in DIRECT_KEYS:
            # A bit hacky here.. IDA looks at '%' as a non-shifted shortcut, but
            # on US keyboards you would need shift to produce '%'. So if the only
            # modifier used with a 'direct key' is Shift, ignore it. This might or
            # might not work for other locales.
            return key

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
    """
    A custom dialog that will show all actions registered with a
    shortcut when one is pressed.

    Actions matching a shortcut are displayed in a QTableWidget.

    Key-presses are intercepted by the table widget with a custom
    keyPressEvent() handler, and turned into shortcuts that can
    be used to look up the corresponding actions.

    ESC to exit.
    """

    def __init__(self):
        self._namer = KeyNamer()
        self._astmap = self._build_ast_map()
        self._shortcut_label = QLabel("Press a shortcut...")
        self._table = self._build_table()
        self._dialog = self._build_dialog()
        self._overlay = self._build_overlay()

    def _build_ast_map(self):
        """Build a Value->Name map of all AST_xxx enum values."""
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
        """Return a Shortcut->Action map of all registered actions."""
        action_map = defaultdict(list)

        actions = ida_kernwin.get_registered_actions()
        for name in actions:
            shortcut = ida_kernwin.get_action_shortcut(name)
            if shortcut:
                action_map[shortcut].append(name)

        return action_map

    def _handle_keyevent(self, event: QKeyEvent, action_map, fn):
        """Intercept key events and update UI with related actions."""
        # First, clear the overlay
        self._dismiss_overlay()

        shortcut = self._namer.keyevent_to_shortcut(event)
        self._set_shortcut(shortcut)
        if DEBUG:
            print("evt: {}  key: {:7X}  native key: {:2X}  native scancode: {:2X}  "
                  "text: {:1}  shortcut: {}".format(
                type(event), event.key(), event.nativeVirtualKey(), event.nativeScanCode(),
                event.text(), shortcut))

        actions = action_map.get(shortcut, []) if shortcut else []
        self._set_data(actions)

        # Only the ESC key goes through
        if event.matches(QKeySequence.Cancel):
            fn(event)

    def _build_table(self) -> QTableWidget:
        """Construct the table widget used to display actions."""
        table = QtWidgets.QTableWidget()
        table.setColumnCount(COLUMN_COUNT)
        table.setRowCount(0)

        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        table.setRangeSelected(QTableWidgetSelectionRange(0, 0, 0, 0), True)
        table.setShowGrid(False)

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

        table.horizontalHeader().setStretchLastSection(False)
        table.horizontalHeader().setSectionResizeMode(COL_TOOLTIP, QHeaderView.Stretch)

        table.setColumnWidth(COL_SHORTCUT, 88)
        table.setColumnWidth(COL_STATE, state_width)
        table.setColumnWidth(COL_VISIBILITY, 25)
        table.setColumnWidth(COL_CHECKABLE, 25)
        table.setColumnWidth(COL_CHECKED, 25)

        for i in range(COLUMN_COUNT):
            table.horizontalHeaderItem(i).setTextAlignment(QtCore.Qt.AlignLeft)

        table.verticalHeader().setHidden(True)
        table.verticalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        table.verticalHeader().setMaximumSectionSize(19)   # TODO: '19' magic constant

        # We build the action map once for the lifetime of the dialog
        action_map = self._build_action_map()
        old_kp = table.keyPressEvent
        table.keyPressEvent = lambda evt: self._handle_keyevent(evt, action_map, old_kp)

        old_resize = table.resizeEvent
        def resizeEvent(evt: QResizeEvent):
            """Size LABEL and ACTION columns proportionally to table width."""
            width = evt.size().width()
            if width != evt.oldSize().width():
                self._table.setColumnWidth(COL_LABEL, width / 5)
                self._table.setColumnWidth(COL_ACTION, width / 5)
            old_resize(evt)

        table.resizeEvent = resizeEvent

        return table

    def _set_shortcut(self, shortcut):
        """Set the current shortcut being displayed by the UI."""
        self._shortcut_label.setText(shortcut)

    def _set_data(self, actions):
        """Set the actions being displayed by the UI (in the table)."""
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
        """Construct the status line for the UI."""
        layout = QHBoxLayout()
        layout.addWidget(QLabel("Shortcut: "))
        layout.addWidget(self._shortcut_label)
        layout.addStretch()
        layout.setContentsMargins(5, 5, 5, 5)
        return layout

    def _build_dialog(self):
        """Construct the main UI dialog."""
        dialog = QDialog()
        dialog.setWindowTitle("Describe Key")
        dialog.resize(800, 200)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._table)
        layout.addLayout(self._build_status())
        dialog.setLayout(layout)

        return dialog

    def _build_overlay(self):
        """
        Construct the initial help overlay.

        The overlay is a 'floating' widget, child of the dialog. It
        will be raised on top of the other widgets (the table), and
        hidden upon the first keypress received.
        """
        label = QLabel("Press a shortcut...", self._dialog)
        label.setStyleSheet("color : #CC3030; font-size: 17px; font-style: italic")
        label.adjustSize()

        px = (self._dialog.width() - label.width()) / 2
        label.move(px, 50)
        label.show()
        label.raise_()

        return label

    def _dismiss_overlay(self):
        """Hide the help overlay, if it exists."""
        if self._overlay:
            self._overlay.hide()
            self._overlay = None

    def show(self):
        """Show the main UI dialog."""
        self._dialog.exec()


class KeyActionHandler(ida_kernwin.action_handler_t):

    def activate(self, ctx):
        # Build a new dialog for every invocation of the action
        dk = DescribeKey()
        dk.show()
        return False

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


def unregister_action():
    """Unregister the DescribeKey action from IDA."""
    ida_kernwin.unregister_action(DESCRIBE_KEY_ACTION)

def register_action():
    """Register the DescribeKey action with IDA."""
    unregister_action()
    desc = ida_kernwin.action_desc_t(
        DESCRIBE_KEY_ACTION,
        DESCRIBE_KEY_TEXT,
        KeyActionHandler(),
        DESCRIBE_KEY_SHORTCUT,
        DESCRIBE_KEY_TOOLTIP)
    return ida_kernwin.register_action(desc)


class DescribeKeyPlugin(ida_idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX  # Always stay loaded, even without an IDB
    wanted_name = DESCRIBE_KEY_TEXT
    wanted_hotkey = DESCRIBE_KEY_SHORTCUT
    comment = DESCRIBE_KEY_TOOLTIP
    help = ""
    version = VERSION

    def init(self):
        return ida_idaapi.PLUGIN_KEEP  # keep us in the memory

    def term(self):
        pass

    def run(self, arg):
        dk = DescribeKey()
        dk.show()


def PLUGIN_ENTRY():
    """Plugin entry point when loaded as a plugin by IDA."""
    return DescribeKeyPlugin()

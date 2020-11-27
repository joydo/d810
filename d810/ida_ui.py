# -*- coding: utf-8 -*-
import os
import json
import logging
import idaapi
import ida_kernwin
from PyQt5 import QtCore, QtWidgets, QtGui

from d810.conf import ProjectConfiguration, RuleConfiguration

logger = logging.getLogger('D810.ui')


class PluginConfigurationFileForm_t(QtWidgets.QDialog):
    def __init__(self, parent, state):
        logger.debug("Initializing PluginConfigurationFileForm_t")
        super().__init__(parent)
        self.state = state
        self.log_dir_changed = False

        self.log_dir = self.state.d810_config.get("log_dir")
        self.erase_logs_on_reload = self.state.d810_config.get("erase_logs_on_reload")
        self.generate_z3_code = self.state.d810_config.get("generate_z3_code")
        self.dump_intermediate_microcode = self.state.d810_config.get("dump_intermediate_microcode")

        self.resize(1000, 500)
        self.setWindowTitle("Plugin Configuration")

        # Main layout
        self.config_layout = QtWidgets.QVBoxLayout(self)

        self.layout_log_dir = QtWidgets.QHBoxLayout()
        self.lbl_log_dir_info = QtWidgets.QLabel(self)
        self.lbl_log_dir_info.setText("Current log directory path: ")
        self.layout_log_dir.addWidget(self.lbl_log_dir_info)
        self.lbl_log_dir = QtWidgets.QLabel(self)
        self.lbl_log_dir.setText(self.log_dir)
        self.layout_log_dir.addWidget(self.lbl_log_dir)
        self.button_change_log_dir = QtWidgets.QPushButton(self)
        self.button_change_log_dir.setText("Change log directory")
        self.button_change_log_dir.clicked.connect(self.choose_log_dir)
        self.layout_log_dir.addWidget(self.button_change_log_dir)

        self.config_layout.addLayout(self.layout_log_dir)

        self.checkbox_generate_z3_code = QtWidgets.QCheckBox("Generate Z3 code for simplification performed", self)
        self.checkbox_generate_z3_code.setChecked(self.state.d810_config.get("generate_z3_code"))
        self.config_layout.addWidget(self.checkbox_generate_z3_code)
        self.checkbox_dump_intermediate_microcode = QtWidgets.QCheckBox("Dump functions microcode at each maturity", self)
        self.checkbox_dump_intermediate_microcode.setChecked(self.state.d810_config.get("dump_intermediate_microcode"))
        self.config_layout.addWidget(self.checkbox_dump_intermediate_microcode)
        self.checkbox_erase_logs_on_reload = QtWidgets.QCheckBox("Erase log directory content when plugin is reloaded", self)
        self.checkbox_erase_logs_on_reload.setChecked(self.state.d810_config.get("erase_logs_on_reload"))
        self.config_layout.addWidget(self.checkbox_erase_logs_on_reload)

        self.layout_button = QtWidgets.QHBoxLayout()
        self.button_save = QtWidgets.QPushButton(self)
        self.button_save.setText("Save")
        self.button_save.clicked.connect(self.save_config)
        self.layout_button.addWidget(self.button_save)
        self.button_cancel = QtWidgets.QPushButton(self)
        self.button_cancel.setText("Cancel")
        self.button_cancel.clicked.connect(self.reject)
        self.layout_button.addWidget(self.button_cancel)
        self.config_layout.addLayout(self.layout_button)

        self.setLayout(self.config_layout)

    def choose_log_dir(self):
        logger.debug("Calling save_rule_configuration")
        log_dir = QtWidgets.QFileDialog.getExistingDirectory(self, "Open Directory", os.path.expanduser("~"),
                                                                  QtWidgets.QFileDialog.ShowDirsOnly |
                                                                  QtWidgets.QFileDialog.DontResolveSymlinks)
        if log_dir != "":
            self.log_dir = log_dir
            self.log_dir_changed = True
            self.lbl_log_dir.setText(self.log_dir)

    def save_config(self):
        if self.log_dir_changed:
            self.state.d810_config.set("log_dir", self.log_dir)
        self.state.d810_config.set("erase_logs_on_reload", self.checkbox_erase_logs_on_reload.isChecked())
        self.state.d810_config.set("generate_z3_code", self.checkbox_generate_z3_code.isChecked())
        self.state.d810_config.set("dump_intermediate_microcode", self.checkbox_dump_intermediate_microcode.isChecked())
        self.state.d810_config.save()
        self.accept()


class EditConfigurationFileForm_t(QtWidgets.QDialog):
    def __init__(self, parent, state):
        logger.debug("Initializing EditConfigurationFileForm_t")
        super().__init__(parent)
        self.state = state
        self.resize(1000, 500)
        self.setWindowTitle("Rule Configuration Editor")

        # Main layout
        self.config_layout = QtWidgets.QVBoxLayout(self)

        # Configuration Name Selection Layout
        self.layout_cfg_name = QtWidgets.QHBoxLayout()
        self.lbl_cfg_name = QtWidgets.QLabel(self)
        self.lbl_cfg_name.setText("Rule Name")
        self.layout_cfg_name.addWidget(self.lbl_cfg_name)
        self.in_cfg_name = QtWidgets.QLineEdit(self)
        self.layout_cfg_name.addWidget(self.in_cfg_name)
        self.config_layout.addLayout(self.layout_cfg_name)

        # Instructions rule Selection Layout
        self.table_ins_rule_selection = QtWidgets.QTableWidget(self)
        # self.table_ins_rule_selection.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table_ins_rule_selection.setRowCount(2)
        self.table_ins_rule_selection.setColumnCount(4)
        item = QtWidgets.QTableWidgetItem()
        item.setText("Is activated")
        self.table_ins_rule_selection.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        item.setText("Rule Name")
        self.table_ins_rule_selection.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        item.setText("Rule Description")
        self.table_ins_rule_selection.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        item.setText("Rule Configuration")
        self.table_ins_rule_selection.setHorizontalHeaderItem(3, item)
        self.table_ins_rule_selection.horizontalHeader().setStretchLastSection(True)
        self.table_ins_rule_selection.verticalHeader().setVisible(False)
        self.table_ins_rule_selection.setSortingEnabled(True)
        # self.table_ins_rule_selection.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.config_layout.addWidget(self.table_ins_rule_selection)

        # Block rule Selection Layout
        self.table_blk_rule_selection = QtWidgets.QTableWidget(self)
        # self.table_blk_rule_selection.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table_blk_rule_selection.setRowCount(2)
        self.table_blk_rule_selection.setColumnCount(4)
        item = QtWidgets.QTableWidgetItem()
        item.setText("Is activated")
        self.table_blk_rule_selection.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        item.setText("Rule Name")
        self.table_blk_rule_selection.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        item.setText("Rule Description")
        self.table_blk_rule_selection.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        item.setText("Rule Configuration")
        self.table_blk_rule_selection.setHorizontalHeaderItem(3, item)
        self.table_blk_rule_selection.horizontalHeader().setStretchLastSection(True)
        self.table_blk_rule_selection.verticalHeader().setVisible(False)
        self.table_blk_rule_selection.setSortingEnabled(True)
        # self.table_blk_rule_selection.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.config_layout.addWidget(self.table_blk_rule_selection)

        self.layout_button = QtWidgets.QHBoxLayout()
        self.button_save = QtWidgets.QPushButton(self)
        self.button_save.setText("Save")
        self.button_save.clicked.connect(self.save_rule_configuration)
        self.layout_button.addWidget(self.button_save)
        self.button_cancel = QtWidgets.QPushButton(self)
        self.button_cancel.setText("Cancel")
        self.button_cancel.clicked.connect(self.reject)
        self.layout_button.addWidget(self.button_cancel)
        self.config_layout.addLayout(self.layout_button)

        self.setLayout(self.config_layout)

        self.config_path = None
        self.config_description = None
        self.config_rules = []
        self.update_table_rule_selection()

    def update_form(self, config_description=None, activated_ins_rule_config_list=None, activated_blk_rule_config_list=None, config_path=None):
        logger.debug("Calling update_form")
        if config_description is not None:
            self.in_cfg_name.setText(config_description)
        if activated_ins_rule_config_list is not None or activated_blk_rule_config_list is not None:
            self.update_table_rule_selection(activated_ins_rule_config_list, activated_blk_rule_config_list)
        if config_path is not None:
            self.config_path = config_path

    def update_table_rule_selection(self, activated_ins_rule_config_list=None, activated_blk_rule_config_list=None):
        logger.debug("Calling update_table_rule_selection")
        self.update_table_ins_rule_selection(activated_ins_rule_config_list)
        self.update_table_blk_rule_selection(activated_blk_rule_config_list)

    def _get_rule_config(self, rule_name, rule_config_list):
        logger.debug("Calling _get_rule_config")
        try:
            rule_name_list = [rule_conf.name for rule_conf in rule_config_list]
            rule_index = rule_name_list.index(rule_name)
            return rule_config_list[rule_index]
        except ValueError:
            return None

    def update_table_ins_rule_selection(self, activated_ins_rule_config_list=None):
        logger.debug("Calling update_table_ins_rule_selection")
        if activated_ins_rule_config_list is None:
            activated_ins_rule_config_list = []
        self.table_ins_rule_selection.setRowCount(len(self.state.known_ins_rules))
        for i, rule in enumerate(self.state.known_ins_rules):
            rule_config = self._get_rule_config(rule.name, activated_ins_rule_config_list)
            item = QtWidgets.QTableWidgetItem()
            item.setTextAlignment(QtCore.Qt.AlignCenter)
            if rule_config is not None and rule_config.is_activated:
                item.setCheckState(QtCore.Qt.Checked)
            else:
                item.setCheckState(QtCore.Qt.Unchecked)
            self.table_ins_rule_selection.setItem(i, 0, item)
            item = QtWidgets.QTableWidgetItem()
            item.setText(rule.name)
            item.setFlags(QtCore.Qt.ItemIsEnabled)
            self.table_ins_rule_selection.setItem(i, 1, item)
            item = QtWidgets.QTableWidgetItem()
            item.setText(rule.description)
            item.setFlags(QtCore.Qt.ItemIsEnabled)
            self.table_ins_rule_selection.setItem(i, 2, item)
            item = QtWidgets.QTableWidgetItem()
            if rule_config is not None:
                item.setText(json.dumps(rule_config.config))
            else:
                item.setText("{}")
            self.table_ins_rule_selection.setItem(i, 3, item)
        self.table_ins_rule_selection.resizeColumnsToContents()

    def update_table_blk_rule_selection(self, activated_blk_rule_config_list=None):
        logger.debug("Calling update_table_blk_rule_selection")
        if activated_blk_rule_config_list is None:
            activated_blk_rule_config_list = []
        self.table_blk_rule_selection.setRowCount(len(self.state.known_blk_rules))
        for i, rule in enumerate(self.state.known_blk_rules):
            rule_config = self._get_rule_config(rule.name, activated_blk_rule_config_list)
            item = QtWidgets.QTableWidgetItem()
            item.setTextAlignment(QtCore.Qt.AlignCenter)
            if rule_config is not None and rule_config.is_activated:
                item.setCheckState(QtCore.Qt.Checked)
            else:
                item.setCheckState(QtCore.Qt.Unchecked)
            self.table_blk_rule_selection.setItem(i, 0, item)
            item = QtWidgets.QTableWidgetItem()
            item.setText(rule.name)
            item.setFlags(QtCore.Qt.ItemIsEnabled)
            self.table_blk_rule_selection.setItem(i, 1, item)
            item = QtWidgets.QTableWidgetItem()
            item.setText(rule.description)
            item.setFlags(QtCore.Qt.ItemIsEnabled)
            self.table_blk_rule_selection.setItem(i, 2, item)
            item = QtWidgets.QTableWidgetItem()
            if rule_config is not None:
                item.setText(json.dumps(rule_config.config))
            else:
                item.setText("{}")
            self.table_blk_rule_selection.setItem(i, 3, item)
        self.table_blk_rule_selection.resizeColumnsToContents()

    def save_rule_configuration(self):
        logger.debug("Calling save_rule_configuration")
        fname, _ = QtWidgets.QFileDialog.getSaveFileName(self, 'Save file', self.config_path, "Project configuration (*.json)")
        if fname:
            self.config_path = fname
            self.config_description = self.in_cfg_name.text()
            self.config_ins_rules = self.get_ins_rules()
            self.config_blk_rules = self.get_blk_rules()
            self.accept()

    def get_ins_rules(self):
        logger.debug("Calling get_ins_rules")
        activated_rule_names = []
        nb_rules = self.table_ins_rule_selection.rowCount()
        for i in range(nb_rules):
            if self.table_ins_rule_selection.item(i, 0).checkState():
                rule_conf = RuleConfiguration(name=self.table_ins_rule_selection.item(i, 1).text(),
                                              is_activated=self.table_ins_rule_selection.item(i, 0).checkState() == QtCore.Qt.Checked,
                                              config=json.loads(self.table_ins_rule_selection.item(i, 3).text()))
                activated_rule_names.append(rule_conf)
                # activated_rule_names.append(self.table_ins_rule_selection.item(i, 1).text())
        return activated_rule_names

    def get_blk_rules(self):
        logger.debug("Calling get_blk_rules")
        activated_rule_names = []
        nb_rules = self.table_blk_rule_selection.rowCount()
        for i in range(nb_rules):
            if self.table_blk_rule_selection.item(i, 0).checkState():
                rule_conf = RuleConfiguration(name=self.table_blk_rule_selection.item(i, 1).text(),
                                              is_activated=self.table_blk_rule_selection.item(i, 0).checkState() == QtCore.Qt.Checked,
                                              config=json.loads(self.table_blk_rule_selection.item(i, 3).text()))
                activated_rule_names.append(rule_conf)
                # activated_rule_names.append(self.table_blk_rule_selection.item(i, 1).text())
        return activated_rule_names


class D810ConfigForm_t(ida_kernwin.PluginForm):
    def __init__(self, state):
        super().__init__()
        self.state = state
        self.shown = False
        self.created = False
        self.parent = None

    def OnClose(self, form):
        logger.debug("Calling OnClose")
        self.shown = False
        # self.parent.close()

    def Show(self):
        logger.debug("Calling Show")
        if self.shown:
            return
        self.shown = True
        return ida_kernwin.PluginForm.Show(
            self, "D-810 Configuration",
            options=(ida_kernwin.PluginForm.WOPN_PERSIST |
                     ida_kernwin.PluginForm.WCLS_SAVE |
                     ida_kernwin.PluginForm.WOPN_MENU |
                     ida_kernwin.PluginForm.WOPN_RESTORE |
                     ida_kernwin.PluginForm.WOPN_TAB))

    def OnCreate(self, form):
        logger.debug("Calling OnCreate")
        self.created = True

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        layout = QtWidgets.QGridLayout(self.parent)

        # ----------- Config options -----------------------
        # Horizontal splitter for config boxes
        cfg_split = QtWidgets.QSplitter(self.parent)
        layout.addWidget(cfg_split, 0, 0)
        # Config name label
        self.curlabel = QtWidgets.QLabel('Current file loaded:')
        cfg_split.addWidget(self.curlabel)

        self.cfg_select = QtWidgets.QComboBox(self.parent)
        cfg_split.addWidget(self.cfg_select)

        self.btn_new_cfg = QtWidgets.QPushButton('New')
        self.btn_new_cfg.clicked.connect(self._create_config)
        cfg_split.addWidget(self.btn_new_cfg)

        self.btn_duplicate_cfg = QtWidgets.QPushButton('Duplicate')
        self.btn_duplicate_cfg.clicked.connect(self._duplicate_config)
        cfg_split.addWidget(self.btn_duplicate_cfg)

        self.btn_edit_cfg = QtWidgets.QPushButton('Edit')
        self.btn_edit_cfg.clicked.connect(self._edit_config)
        cfg_split.addWidget(self.btn_edit_cfg)

        self.btn_delele_cfg = QtWidgets.QPushButton('Delete')
        self.btn_delele_cfg.clicked.connect(self._delete_config)
        cfg_split.addWidget(self.btn_delele_cfg)

        # leave space for comboboxes in cfg_split, rather than between widgets
        cfg_split.setStretchFactor(0, 0)
        cfg_split.setStretchFactor(1, 1)
        cfg_split.setStretchFactor(2, 0)

        description_split = QtWidgets.QSplitter(self.parent)
        layout.addWidget(description_split, 1, 0)
        self.cfg_description_layout = QtWidgets.QHBoxLayout(description_split)
        self.cfg_description_label = QtWidgets.QLabel("Description")
        description_split.addWidget(self.cfg_description_label)
        self.cfg_description = QtWidgets.QLabel("No description")
        description_split.addWidget(self.cfg_description)
        description_split.setStretchFactor(0, 0)
        description_split.setStretchFactor(1, 1)

        self.cfg_ins_preview = QtWidgets.QTableWidget(self.parent)
        layout.addWidget(self.cfg_ins_preview, 2, 0)

        self.cfg_blk_preview = QtWidgets.QTableWidget(self.parent)
        layout.addWidget(self.cfg_blk_preview, 3, 0)
        self.update_cfg_preview()

        # ----------- Analysis buttons -----------------------
        # Horizontal splitter for buttons
        btn_split = QtWidgets.QSplitter(self.parent)
        layout.addWidget(btn_split, 4, 0)

        self.btn_config = QtWidgets.QPushButton('Configuration')
        self.btn_config.clicked.connect(self._configure_plugin)
        btn_split.addWidget(self.btn_config)


        self.btn_start = QtWidgets.QPushButton('Start')
        self.btn_start.clicked.connect(self._start_d810)
        btn_split.addWidget(self.btn_start)

        self.btn_stop = QtWidgets.QPushButton('Stop')
        self.btn_stop.clicked.connect(self._stop_d810)
        btn_split.addWidget(self.btn_stop)

        self.plugin_status = QtWidgets.QLabel()
        self.plugin_status.setText("<span style=\" font-size:8pt; font-weight:600; color:#ff0000;\" >Not Loaded</span>")
        description_split.addWidget(self.plugin_status)
        btn_split.addWidget(self.plugin_status)


        self.update_cfg_select()
        self.cfg_select.setCurrentIndex(self.state.current_project_index)
        self.cfg_select.currentIndexChanged.connect(self._load_config)

    def update_cfg_preview(self):
        logger.debug("Calling update_cfg_preview")
        self.update_cfg_ins_preview()
        self.update_cfg_blk_preview()

    def update_cfg_ins_preview(self):
        # return
        logger.debug("Calling update_cfg_ins_preview")
        self.cfg_ins_preview.setRowCount(len(self.state.current_ins_rules))
        self.cfg_ins_preview.setColumnCount(3)
        self.cfg_ins_preview.setHorizontalHeaderLabels(("Name", "Description", "Configuration"))
        self.cfg_ins_preview.horizontalHeader().setStretchLastSection(True)
        self.cfg_ins_preview.setSortingEnabled(True)
        # self.cfg_ins_preview.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        i = 0
        for rule in self.state.current_ins_rules:
            cell_file_path = QtWidgets.QTableWidgetItem(rule.name)
            cell_file_path.setFlags(QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled)
            cell_rule_description = QtWidgets.QTableWidgetItem(rule.description)
            cell_rule_description.setFlags(QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled)
            cell_rule_config = QtWidgets.QTableWidgetItem(json.dumps(rule.config))
            cell_rule_config.setFlags(QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled)
            self.cfg_ins_preview.setItem(i, 0, cell_file_path)
            self.cfg_ins_preview.setItem(i, 1, cell_rule_description)
            self.cfg_ins_preview.setItem(i, 2, cell_rule_config)
            i += 1
        self.cfg_ins_preview.resizeColumnsToContents()

    def update_cfg_blk_preview(self):
        logger.debug("Calling update_cfg_blk_preview")
        self.cfg_blk_preview.setRowCount(len(self.state.current_blk_rules))
        self.cfg_blk_preview.setColumnCount(3)
        self.cfg_blk_preview.setHorizontalHeaderLabels(("Name", "Description", "Configuration"))
        self.cfg_blk_preview.horizontalHeader().setStretchLastSection(True)
        self.cfg_blk_preview.setSortingEnabled(True)
        # self.cfg_blk_preview.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        i = 0
        for rule in self.state.current_blk_rules:
            cell_file_path = QtWidgets.QTableWidgetItem(rule.name)
            cell_file_path.setFlags(QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled)
            cell_rule_description = QtWidgets.QTableWidgetItem(rule.description)
            cell_rule_description.setFlags(QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled)
            cell_rule_config = QtWidgets.QTableWidgetItem(json.dumps(rule.config))
            cell_rule_config.setFlags(QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled)
            self.cfg_blk_preview.setItem(i, 0, cell_file_path)
            self.cfg_blk_preview.setItem(i, 1, cell_rule_description)
            self.cfg_blk_preview.setItem(i, 2, cell_rule_config)
            i += 1
        self.cfg_blk_preview.resizeColumnsToContents()

    def update_cfg_select(self):
        logger.debug("Calling update_cfg_select")
        tmp = self.state.current_project_index
        self.cfg_select.clear()
        self.cfg_select.addItems([proj.path for proj in self.state.projects])
        self.cfg_select.setCurrentIndex(tmp)

    def _create_config(self):
        logger.debug("Calling _create_config")
        self._internal_config_creation(None, None, None, self.state.d810_config.config_dir)

    def _duplicate_config(self):
        logger.debug("Calling _duplicate_config")
        cur_cfg = self.state.current_project
        self._internal_config_creation(None, cur_cfg.ins_rules, cur_cfg.blk_rules, self.state.d810_config.config_dir)

    def _edit_config(self):
        logger.debug("Calling _edit_config")
        cur_cfg = self.state.current_project
        self._internal_config_creation(cur_cfg.description, cur_cfg.ins_rules, cur_cfg.blk_rules, cur_cfg.path, cur_cfg)

    def _internal_config_creation(self, description, start_ins_rules, start_blk_rules, path, old_conf=None):
        logger.debug("Calling _internal_config_creation")
        editdlg = EditConfigurationFileForm_t(self.parent, self.state)
        editdlg.update_form(description, start_ins_rules, start_blk_rules, path)
        if editdlg.exec_() == QtWidgets.QDialog.Accepted:
            new_config = ProjectConfiguration(editdlg.config_path, editdlg.config_description, editdlg.config_ins_rules, editdlg.config_blk_rules)
            new_config.save()
            if old_conf is None:
                self.state.add_project(new_config)
            else:
                self.state.update_project(old_conf, new_config)
            self.update_cfg_select()
            return new_config
        return None

    # callback when the "Delete" button is clicked
    def _delete_config(self):
        logger.debug("Calling _delete_config")
        self.state.del_project(self.state.current_project)
        self.update_cfg_select()

    # Called when the edit combo is changed
    def _load_config(self, index):
        logger.debug("Calling _load_config")
        self.state.load_project(index)
        self.cfg_description.setText(self.state.current_project.description)
        self.update_cfg_preview()
        return

    def _configure_plugin(self):
        editdlg = PluginConfigurationFileForm_t(self.parent, self.state)
        if editdlg.exec_() == QtWidgets.QDialog.Accepted:
            return
        return

    def _start_d810(self):
        logger.debug("Calling _start_d810")
        self.state.start_d810()
        # self.plugin_status.clear()
        self.plugin_status.setText("<span style=\" font-size:8pt; font-weight:600; color:#00FF00;\" >Loaded</span>")
        return

    def _stop_d810(self):
        logger.debug("Calling _stop_d810")
        self.state.stop_d810()
        # self.plugin_status.clear()
        self.plugin_status.setText("<span style=\" font-size:8pt; font-weight:600; color:#FF0000;\" >Not Loaded</span>")
        return


class D810GUI(object):
    def __init__(self, state):
        """
        Instanciate D-810 views
        """
        logger.debug("Initializing D810GUI")
        self.state = state
        self.d810_config_form = D810ConfigForm_t(self.state)
        # XXX fix
        idaapi.set_dock_pos("D-810", "IDA View-A", idaapi.DP_TAB)

    def show_windows(self):
        logger.debug("Calling show_windows")
        self.d810_config_form.Show()

    def term(self):
        logger.debug("Calling term")
        self.d810_config_form.Close(ida_kernwin.PluginForm.WCLS_SAVE)

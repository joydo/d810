from __future__ import annotations
import os
import json
import logging
import idaapi

from typing import TYPE_CHECKING, List
if TYPE_CHECKING:
    from d810.conf import D810Configuration, ProjectConfiguration


# Note that imports are performed directly in the functions so that they are reloaded each time the plugin is restarted
# This allow to load change code/drop new rules without having to reboot IDA
d810_state = None

D810_LOG_DIR_NAME = "d810_logs"

MANAGER_INFO_FILENAME = "manager_info.json"
logger = logging.getLogger('D810')


def reload_all_modules():
    manager_info_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), MANAGER_INFO_FILENAME)

    with open(manager_info_path, "r") as f:
        manager_info = json.load(f)

    for module_name in manager_info["module_list"]:
        idaapi.require(module_name)


class D810Manager(object):
    def __init__(self, log_dir):
        self.instruction_optimizer_rules = []
        self.instruction_optimizer_config = {}
        self.block_optimizer_rules = []
        self.block_optimizer_config = {}
        self.instruction_optimizer = None
        self.block_optimizer = None
        self.hx_decompiler_hook = None
        self.log_dir = log_dir
        self.config = {}

    def configure(self, **kwargs):
        self.config = kwargs

    def reload(self):
        self.stop()
        logger.debug("Reloading manager...")

        from d810.hexrays_hooks import InstructionOptimizerManager, BlockOptimizerManager, HexraysDecompilationHook

        self.instruction_optimizer = InstructionOptimizerManager(self)
        self.instruction_optimizer.configure(**self.instruction_optimizer_config)
        self.block_optimizer = BlockOptimizerManager(self)
        self.block_optimizer.configure(**self.block_optimizer_config)

        for rule in self.instruction_optimizer_rules:
            rule.log_dir = self.log_dir
            self.instruction_optimizer.add_rule(rule)

        for cfg_rule in self.block_optimizer_rules:
            cfg_rule.log_dir = self.log_dir
            self.block_optimizer.add_rule(cfg_rule)

        self.instruction_optimizer.install()
        self.block_optimizer.install()

        self.hx_decompiler_hook = HexraysDecompilationHook(self)
        self.hx_decompiler_hook.hook()

    def configure_instruction_optimizer(self, rules, **kwargs):
        self.instruction_optimizer_rules = [rule for rule in rules]
        self.instruction_optimizer_config = kwargs

    def configure_block_optimizer(self, rules, **kwargs):
        self.block_optimizer_rules = [rule for rule in rules]
        self.block_optimizer_config = kwargs

    def stop(self):
        if self.instruction_optimizer is not None:
            logger.debug("Removing InstructionOptimizer...")
            self.instruction_optimizer.remove()
            self.instruction_optimizer = None
        if self.block_optimizer is not None:
            logger.debug("Removing ControlFlowFixer...")
            self.block_optimizer.remove()
            self.block_optimizer = None
        if self.hx_decompiler_hook is not None:
            logger.debug("Removing HexraysDecompilationHook...")
            self.hx_decompiler_hook.unhook()
            self.hx_decompiler_hook = None


class D810State(object):
    def __init__(self, d810_config: D810Configuration):
        # For debugging purposes, to interact with this object from the console
        # Type in IDA Python shell 'from d810.manager import d810_state' to access it
        global d810_state
        d810_state = self
        reload_all_modules()

        self.d810_config = d810_config
        self.log_dir = os.path.join(self.d810_config.get("log_dir"), D810_LOG_DIR_NAME)
        self.manager = D810Manager(self.log_dir)

        from d810.optimizers.instructions import KNOWN_INS_RULES
        from d810.optimizers.flow import KNOWN_BLK_RULES
        self.known_ins_rules = [x for x in KNOWN_INS_RULES]
        self.known_blk_rules = [x for x in KNOWN_BLK_RULES]

        self.gui = None
        self.current_project = None
        self.projects: List[ProjectConfiguration] = []
        self.current_project_index = self.d810_config.get("last_project_index")
        self.current_ins_rules = []
        self.current_blk_rules = []

        self.register_default_projects()
        self.load_project(self.current_project_index)

    def register_default_projects(self):
        from d810.conf import ProjectConfiguration
        self.projects = []
        for project_configuration_path in self.d810_config.get("configurations"):
            project_configuration = ProjectConfiguration(project_configuration_path,
                                                         conf_dir=self.d810_config.config_dir)
            project_configuration.load()
            self.projects.append(project_configuration)
        logger.debug("Rule configurations loaded: {0}".format(self.projects))

    def add_project(self, config: ProjectConfiguration):
        self.projects.append(config)
        self.d810_config.get("configurations").append(config.path)
        self.d810_config.save()

    def update_project(self, old_config: ProjectConfiguration, new_config: ProjectConfiguration):
        old_config_index = self.projects.index(old_config)
        self.projects[old_config_index] = new_config

    def del_project(self, config: ProjectConfiguration):
        self.projects.remove(config)
        self.d810_config.get("configurations").remove(config.path)
        self.d810_config.save()
        os.remove(config.path)

    def load_project(self, project_index: int):
        self.current_project_index = project_index
        self.current_project = self.projects[project_index]
        self.current_ins_rules = []
        self.current_blk_rules = []

        for rule in self.known_ins_rules:
            for rule_conf in self.current_project.ins_rules:
                if rule.name == rule_conf.name:
                    rule.configure(rule_conf.config)
                    rule.set_log_dir(self.log_dir)
                    self.current_ins_rules.append(rule)
        logger.debug("Instruction rules configured")
        for blk_rule in self.known_blk_rules:
            for rule_conf in self.current_project.blk_rules:
                if blk_rule.name == rule_conf.name:
                    blk_rule.configure(rule_conf.config)
                    blk_rule.set_log_dir(self.log_dir)
                    self.current_blk_rules.append(blk_rule)
        logger.debug("Block rules configured")
        self.manager.configure(**self.current_project.additional_configuration)
        logger.debug("Project loaded.")

    def start_d810(self):
        print("D-810 ready to deobfuscate...")
        self.manager.configure_instruction_optimizer([rule for rule in self.current_ins_rules],
                                                     generate_z3_code=self.d810_config.get("generate_z3_code"),
                                                     dump_intermediate_microcode=self.d810_config.get(
                                                         "dump_intermediate_microcode"),
                                                     **self.current_project.additional_configuration)
        self.manager.configure_block_optimizer([rule for rule in self.current_blk_rules],
                                               **self.current_project.additional_configuration)
        self.manager.reload()
        self.d810_config.set("last_project_index", self.current_project_index)
        self.d810_config.save()

    def stop_d810(self):
        print("Stopping D-810...")
        self.manager.stop()

    def start_plugin(self):
        from d810.ida_ui import D810GUI
        self.gui = D810GUI(self)
        self.gui.show_windows()

    def stop_plugin(self):
        self.manager.stop()
        if self.gui:
            self.gui.term()
            self.gui = None

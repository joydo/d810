from __future__ import annotations
import logging
from typing import List, Union, Tuple

from ida_hexrays import *

from d810.optimizers.flow.handler import FlowOptimizationRule

from d810.tracker import MopTracker, MopHistory, remove_segment_registers, duplicate_histories
from d810.emulator import MicroCodeEnvironment, MicroCodeInterpreter
from d810.hexrays_hooks import InstructionDefUseCollector
from d810.hexrays_helpers import extract_num_mop, get_mop_index, append_mop_if_not_in_list, CONTROL_FLOW_OPCODES, \
    CONDITIONAL_JUMP_OPCODES
from d810.hexrays_formatters import format_minsn_t, format_mop_t, dump_microcode_for_debug, format_mop_list
from d810.cfg_utils import mba_deep_cleaning, ensure_child_has_an_unconditional_father, ensure_last_block_is_goto, \
    change_1way_block_successor, create_block
from d810.optimizers.flow.flattening.utils import NotResolvableFatherException, NotDuplicableFatherException, \
    DispatcherUnflatteningException, get_all_possibles_values, check_if_all_values_are_found

unflat_logger = logging.getLogger('D810.unflat')


class GenericDispatcherBlockInfo(object):

    def __init__(self, blk, father=None):
        self.blk = blk
        self.ins = []
        self.use_list = []
        self.use_before_def_list = []
        self.def_list = []
        self.assume_def_list = []
        self.comparison_value = None
        self.compared_mop = None

        self.father = None
        if father is not None:
            self.register_father(father)

    @property
    def serial(self) -> int:
        return self.blk.serial

    def register_father(self, father: GenericDispatcherBlockInfo):
        self.father = father
        self.assume_def_list = [x for x in father.assume_def_list]

    def update_use_def_lists(self, ins_mops_used: List[mop_t], ins_mops_def: List[mop_t]):
        for mop_used in ins_mops_used:
            append_mop_if_not_in_list(mop_used, self.use_list)
            mop_used_index = get_mop_index(mop_used, self.def_list)
            if mop_used_index == -1:
                append_mop_if_not_in_list(mop_used, self.use_before_def_list)
        for mop_def in ins_mops_def:
            append_mop_if_not_in_list(mop_def, self.def_list)

    def update_with_ins(self, ins: minsn_t):
        ins_mop_info = InstructionDefUseCollector()
        ins.for_all_ops(ins_mop_info)
        cleaned_unresolved_ins_mops = remove_segment_registers(ins_mop_info.unresolved_ins_mops)
        self.update_use_def_lists(cleaned_unresolved_ins_mops + ins_mop_info.memory_unresolved_ins_mops,
                                  ins_mop_info.target_mops)
        self.ins.append(ins)
        if ins.opcode in CONDITIONAL_JUMP_OPCODES:
            num_mop, other_mop = extract_num_mop(ins)
            if num_mop is not None:
                self.comparison_value = num_mop.nnn.value
                self.compared_mop = other_mop

    def parse(self):
        curins = self.blk.head
        while curins is not None:
            self.update_with_ins(curins)
            curins = curins.next
        for mop_def in self.def_list:
            append_mop_if_not_in_list(mop_def, self.assume_def_list)

    def does_only_need(self, prerequisite_mop_list: List[mop_t]) -> bool:
        for used_before_def_mop in self.use_before_def_list:
            mop_index = get_mop_index(used_before_def_mop, prerequisite_mop_list)
            if mop_index == -1:
                return False
        return True

    def recursive_get_father(self) -> List[GenericDispatcherBlockInfo]:
        if self.father is None:
            return [self]
        else:
            return self.father.recursive_get_father() + [self]

    def show_history(self):
        full_father_list = self.recursive_get_father()
        unflat_logger.info("    Show history of Block {0}".format(self.blk.serial))
        for father in full_father_list[:-1]:
            for ins in father.ins:
                unflat_logger.info("      {0}.{1}".format(father.blk.serial, format_minsn_t(ins)))

    def print_info(self):
        unflat_logger.info("Block {0} information:".format(self.blk.serial))
        unflat_logger.info("  USE list: {0}".format(format_mop_list(self.use_list)))
        unflat_logger.info("  DEF list: {0}".format(format_mop_list(self.def_list)))
        unflat_logger.info("  USE BEFORE DEF list: {0}".format(format_mop_list(self.use_before_def_list)))
        unflat_logger.info("  ASSUME DEF list: {0}".format(format_mop_list(self.assume_def_list)))


class GenericDispatcherInfo(object):
    def __init__(self, mba: mbl_array_t):
        self.mba = mba
        self.mop_compared = None
        self.entry_block = None
        self.comparison_values = []
        self.dispatcher_internal_blocks = []
        self.dispatcher_exit_blocks = []

    def reset(self):
        self.mop_compared = None
        self.entry_block = None
        self.comparison_values = []
        self.dispatcher_internal_blocks = []
        self.dispatcher_exit_blocks = []

    def explore(self, blk: mblock_t) -> bool:
        return False

    def get_shared_internal_blocks(self, other_dispatcher: GenericDispatcherInfo) -> List[mblock_t]:
        my_dispatcher_block_serial = [blk_info.blk.serial for blk_info in self.dispatcher_internal_blocks]
        other_dispatcher_block_serial = [blk_info.blk.serial
                                         for blk_info in other_dispatcher.dispatcher_internal_blocks]
        return [self.mba.get_mblock(blk_serial) for blk_serial in my_dispatcher_block_serial
                if blk_serial in other_dispatcher_block_serial]

    def is_sub_dispatcher(self, other_dispatcher: GenericDispatcherInfo) -> bool:
        shared_blocks = self.get_shared_internal_blocks(other_dispatcher)
        if (len(shared_blocks) > 0) and (self.entry_block.blk.npred() < other_dispatcher.entry_block.blk.npred()):
            return True
        return False

    def should_emulation_continue(self, cur_blk: mblock_t) -> bool:
        exit_block_serial_list = [exit_block.serial for exit_block in self.dispatcher_exit_blocks]
        if (cur_blk is not None) and (cur_blk.serial not in exit_block_serial_list):
            return True
        return False

    def emulate_dispatcher_with_father_history(self, father_history: MopHistory) -> Tuple[mblock_t, List[minsn_t]]:
        microcode_interpreter = MicroCodeInterpreter()
        microcode_environment = MicroCodeEnvironment()
        dispatcher_input_info = []
        for initialization_mop in self.entry_block.use_before_def_list:
            initialization_mop_value = father_history.get_mop_constant_value(initialization_mop)
            if initialization_mop_value is None:
                raise NotResolvableFatherException("Can't emulate dispatcher {0} with history {1}"
                                                   .format(self.entry_block.serial, father_history.block_serial_path))
            microcode_environment.define(initialization_mop, initialization_mop_value)
            dispatcher_input_info.append("{0} = {1:x}".format(format_mop_t(initialization_mop),
                                                              initialization_mop_value))

        unflat_logger.info("Executing dispatcher {0} with: {1}"
                           .format(self.entry_block.blk.serial, ", ".join(dispatcher_input_info)))

        instructions_executed = []
        cur_blk = self.entry_block.blk
        cur_ins = cur_blk.head
        while self.should_emulation_continue(cur_blk):
            unflat_logger.debug("  Executing: {0}.{1}".format(cur_blk.serial, format_minsn_t(cur_ins)))
            is_ok = microcode_interpreter.eval_instruction(cur_blk, cur_ins, microcode_environment)
            if not is_ok:
                return cur_blk, instructions_executed
            instructions_executed.append(cur_ins)
            cur_blk = microcode_environment.next_blk
            cur_ins = microcode_environment.next_ins
        return cur_blk, instructions_executed

    def print_info(self, verbose=False):
        unflat_logger.info("Dispatcher information: ")
        unflat_logger.info("  Entry block: {0}.{1}: ".format(self.entry_block.blk.serial,
                                                             format_minsn_t(self.entry_block.blk.tail)))
        unflat_logger.info("  Entry block predecessors: {0}: "
                           .format([blk_serial for blk_serial in self.entry_block.blk.predset]))
        unflat_logger.info("    Compared mop: {0} ".format(format_mop_t(self.mop_compared)))
        unflat_logger.info("    Comparison values: {0} ".format(", ".join([hex(x) for x in self.comparison_values])))
        self.entry_block.print_info()
        unflat_logger.info("  Number of internal blocks: {0} ({1})"
                           .format(len(self.dispatcher_internal_blocks),
                                   [blk_info.blk.serial for blk_info in self.dispatcher_internal_blocks]))
        if verbose:
            for disp_blk in self.dispatcher_internal_blocks:
                unflat_logger.info("    Internal block: {0}.{1} ".format(disp_blk.blk.serial,
                                                                         format_minsn_t(disp_blk.blk.tail)))
                disp_blk.show_history()
        unflat_logger.info("  Number of Exit blocks: {0} ({1})"
                           .format(len(self.dispatcher_exit_blocks),
                                   [blk_info.blk.serial for blk_info in self.dispatcher_exit_blocks]))
        if verbose:
            for exit_blk in self.dispatcher_exit_blocks:
                unflat_logger.info("    Exit block: {0}.{1} ".format(exit_blk.blk.serial,
                                                                     format_minsn_t(exit_blk.blk.head)))
                exit_blk.show_history()


class GenericDispatcherCollector(minsn_visitor_t):
    DISPATCHER_CLASS = GenericDispatcherInfo
    DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK = 2
    DEFAULT_DISPATCHER_MIN_EXIT_BLOCK = 2
    DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE = 2

    def __init__(self):
        super().__init__()
        self.dispatcher_list = []
        self.explored_blk_serials = []
        self.dispatcher_min_internal_block = self.DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK
        self.dispatcher_min_exit_block = self.DEFAULT_DISPATCHER_MIN_EXIT_BLOCK
        self.dispatcher_min_comparison_value = self.DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE

    def configure(self, kwargs):
        if "min_dispatcher_internal_block" in kwargs.keys():
            self.dispatcher_min_internal_block = kwargs["min_dispatcher_internal_block"]
        if "min_dispatcher_exit_block" in kwargs.keys():
            self.dispatcher_min_exit_block = kwargs["min_dispatcher_exit_block"]
        if "min_dispatcher_comparison_value" in kwargs.keys():
            self.dispatcher_min_comparison_value = kwargs["min_dispatcher_comparison_value"]

    def specific_checks(self, disp_info: GenericDispatcherInfo) -> bool:
        unflat_logger.debug("DispatcherInfo {0} : {1} internals, {2} exits, {3} comparison"
                            .format(self.blk.serial, len(disp_info.dispatcher_internal_blocks),
                                    len(disp_info.dispatcher_exit_blocks), len(set(disp_info.comparison_values))))
        if len(disp_info.dispatcher_internal_blocks) < self.dispatcher_min_internal_block:
            return False
        if len(disp_info.dispatcher_exit_blocks) < self.dispatcher_min_exit_block:
            return False
        if len(set(disp_info.comparison_values)) < self.dispatcher_min_comparison_value:
            return False
        self.dispatcher_list.append(disp_info)
        return True

    def visit_minsn(self):
        if self.blk.serial in self.explored_blk_serials:
            return 0
        self.explored_blk_serials.append(self.blk.serial)
        disp_info = self.DISPATCHER_CLASS(self.blk.mba)
        is_good_candidate = disp_info.explore(self.blk)
        if not is_good_candidate:
            return 0
        if not self.specific_checks(disp_info):
            return 0
        self.dispatcher_list.append(disp_info)
        return 0

    def remove_sub_dispatchers(self):
        main_dispatcher_list = []
        for dispatcher_1 in self.dispatcher_list:
            is_dispatcher_1_sub_dispatcher = False
            for dispatcher_2 in self.dispatcher_list:
                if dispatcher_1.is_sub_dispatcher(dispatcher_2):
                    is_dispatcher_1_sub_dispatcher = True
                    break
            if not is_dispatcher_1_sub_dispatcher:
                main_dispatcher_list.append(dispatcher_1)
        self.dispatcher_list = [x for x in main_dispatcher_list]

    def reset(self):
        self.dispatcher_list = []
        self.explored_blk_serials = []

    def get_dispatcher_list(self) -> List[GenericDispatcherInfo]:
        self.remove_sub_dispatchers()
        return self.dispatcher_list


class GenericUnflatteningRule(FlowOptimizationRule):
    DEFAULT_UNFLATTENING_MATURITIES = [MMAT_CALLS, MMAT_GLBOPT1, MMAT_GLBOPT2]

    def __init__(self):
        super().__init__()
        self.mba = None
        self.cur_maturity = MMAT_ZERO
        self.cur_maturity_pass = 0
        self.last_pass_nb_patch_done = 0
        self.maturities = self.DEFAULT_UNFLATTENING_MATURITIES

    def check_if_rule_should_be_used(self, blk: mblock_t) -> bool:
        if self.cur_maturity == self.mba.maturity:
            self.cur_maturity_pass += 1
        else:
            self.cur_maturity = self.mba.maturity
            self.cur_maturity_pass = 0
        if self.cur_maturity not in self.maturities:
            return False
        return True


class GenericDispatcherUnflatteningRule(GenericUnflatteningRule):
    DISPATCHER_COLLECTOR_CLASS = GenericDispatcherCollector
    MOP_TRACKER_MAX_NB_BLOCK = 100
    MOP_TRACKER_MAX_NB_PATH = 100
    DEFAULT_MAX_DUPLICATION_PASSES = 20
    DEFAULT_MAX_PASSES = 5

    def __init__(self):
        super().__init__()
        self.dispatcher_collector = self.DISPATCHER_COLLECTOR_CLASS()
        self.dispatcher_list = []
        self.max_duplication_passes = self.DEFAULT_MAX_DUPLICATION_PASSES
        self.max_passes = self.DEFAULT_MAX_PASSES

    def check_if_rule_should_be_used(self, blk: mblock_t) -> bool:
        if not super().check_if_rule_should_be_used(blk):
            return False
        if (self.cur_maturity_pass >= 1) and (self.last_pass_nb_patch_done == 0):
            return False
        if (self.max_passes is not None) and (self.cur_maturity_pass >= self.max_passes):
            return False
        return True

    def configure(self, kwargs):
        super().configure(kwargs)
        if "max_passes" in self.config.keys():
            self.max_passes = self.config["max_passes"]
        if "max_duplication_passes" in self.config.keys():
            self.max_duplication_passes = self.config["max_duplication_passes"]
        self.dispatcher_collector.configure(kwargs)

    def retrieve_all_dispatchers(self):
        self.dispatcher_list = []
        self.dispatcher_collector.reset()
        self.mba.for_all_topinsns(self.dispatcher_collector)
        self.dispatcher_list = [x for x in self.dispatcher_collector.get_dispatcher_list()]

    def ensure_all_dispatcher_fathers_are_direct(self) -> int:
        nb_change = 0
        for dispatcher_info in self.dispatcher_list:
            dispatcher_father_list = [self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset]
            for dispatcher_father in dispatcher_father_list:
                nb_change += ensure_child_has_an_unconditional_father(dispatcher_father,
                                                                      dispatcher_info.entry_block.blk)
        return nb_change

    def register_initialization_variables(self, mop_tracker):
        pass

    def get_dispatcher_father_histories(self, dispatcher_father: mblock_t,
                                        dispatcher_entry_block: GenericDispatcherBlockInfo) -> List[MopHistory]:
        father_tracker = MopTracker(dispatcher_entry_block.use_before_def_list,
                                    max_nb_block=self.MOP_TRACKER_MAX_NB_BLOCK, max_path=self.MOP_TRACKER_MAX_NB_PATH)
        father_tracker.reset()
        self.register_initialization_variables(father_tracker)
        father_histories = father_tracker.search_backward(dispatcher_father, None)
        return father_histories

    def check_if_histories_are_resolved(self, mop_histories: List[MopHistory]) -> bool:
        return all([mop_history.is_resolved() for mop_history in mop_histories])

    def ensure_dispatcher_father_is_resolvable(self, dispatcher_father: mblock_t,
                                               dispatcher_entry_block: GenericDispatcherBlockInfo) -> int:
        father_histories = self.get_dispatcher_father_histories(dispatcher_father, dispatcher_entry_block)
        father_histories_cst = get_all_possibles_values(father_histories, dispatcher_entry_block.use_before_def_list,
                                                        verbose=False)
        father_is_resolvable = self.check_if_histories_are_resolved(father_histories)
        if not father_is_resolvable:
            raise NotDuplicableFatherException("Dispatcher {0} predecessor {1} is not duplicable: {2}"
                                               .format(dispatcher_entry_block.serial, dispatcher_father.serial,
                                                       father_histories_cst))

        unflat_logger.info("Dispatcher {0} predecessor {1} is resolvable: {2}"
                           .format(dispatcher_entry_block.serial, dispatcher_father.serial, father_histories_cst))
        nb_duplication, nb_change = duplicate_histories(father_histories, max_nb_pass=self.max_duplication_passes)
        unflat_logger.info("Dispatcher {0} predecessor {1} duplication: {2} blocks created, {3} changes made"
                           .format(dispatcher_entry_block.serial, dispatcher_father.serial, nb_duplication, nb_change))
        return nb_duplication + nb_change

    def resolve_dispatcher_father(self, dispatcher_father: mblock_t, dispatcher_info: GenericDispatcherInfo) -> int:
        dispatcher_father_histories = self.get_dispatcher_father_histories(dispatcher_father,
                                                                           dispatcher_info.entry_block)
        father_is_resolvable = self.check_if_histories_are_resolved(dispatcher_father_histories)
        if not father_is_resolvable:
            raise NotResolvableFatherException("Can't fix block {0}".format(dispatcher_father.serial))
        mop_searched_values_list = get_all_possibles_values(dispatcher_father_histories,
                                                            dispatcher_info.entry_block.use_before_def_list,
                                                            verbose=False)
        all_values_found = check_if_all_values_are_found(mop_searched_values_list)
        if not all_values_found:
            raise NotResolvableFatherException("Can't fix block {0}".format(dispatcher_father.serial))

        ref_mop_searched_values = mop_searched_values_list[0]
        for tmp_mop_searched_values in mop_searched_values_list:
            if tmp_mop_searched_values != ref_mop_searched_values:
                raise NotResolvableFatherException("Dispatcher {0} predecessor {1} is not resolvable: {2}"
                                                   .format(dispatcher_info.entry_block.serial, dispatcher_father.serial,
                                                           mop_searched_values_list))

        target_blk, disp_ins = dispatcher_info.emulate_dispatcher_with_father_history(dispatcher_father_histories[0])
        if target_blk is not None:
            unflat_logger.debug("Unflattening graph: Making {0} goto {1}"
                                .format(dispatcher_father.serial, target_blk.serial))
            ins_to_copy = [ins for ins in disp_ins if ((ins is not None) and (ins.opcode not in CONTROL_FLOW_OPCODES))]
            if len(ins_to_copy) > 0:
                unflat_logger.info("Instruction copied: {0}: {1}"
                                   .format(len(ins_to_copy),
                                           ", ".join([format_minsn_t(ins_copied) for ins_copied in ins_to_copy])))
                dispatcher_side_effect_blk = create_block(self.mba.get_mblock(self.mba.qty - 2), ins_to_copy,
                                                          is_0_way=(target_blk.type == BLT_0WAY))
                change_1way_block_successor(dispatcher_father, dispatcher_side_effect_blk.serial)
                change_1way_block_successor(dispatcher_side_effect_blk, target_blk.serial)
            else:
                change_1way_block_successor(dispatcher_father, target_blk.serial)
            return 2

        raise NotResolvableFatherException("Can't fix block {0}: no block for key: {1}"
                                           .format(dispatcher_father.serial, mop_searched_values_list))

    def remove_flattening(self) -> int:
        total_nb_change = ensure_last_block_is_goto(self.mba)
        total_nb_change += self.ensure_all_dispatcher_fathers_are_direct()
        nb_flattened_branches = 0
        for dispatcher_info in self.dispatcher_list:
            dump_microcode_for_debug(self.mba, self.log_dir, "unflat_{0}_dispatcher_{1}_before_duplication"
                                     .format(self.cur_maturity_pass, dispatcher_info.entry_block.serial))
            unflat_logger.info("Searching dispatcher for entry block {0} {1} ->  with variables ({2})..."
                               .format(dispatcher_info.entry_block.serial, format_mop_t(dispatcher_info.mop_compared),
                                       format_mop_list(dispatcher_info.entry_block.use_before_def_list)))
            dispatcher_father_list = [self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset]
            for dispatcher_father in dispatcher_father_list:
                try:
                    total_nb_change += self.ensure_dispatcher_father_is_resolvable(dispatcher_father,
                                                                                   dispatcher_info.entry_block)
                except NotDuplicableFatherException as e:
                    unflat_logger.warning(e)
                    pass
            dump_microcode_for_debug(self.mba, self.log_dir, "unflat_{0}_dispatcher_{1}_after_duplication"
                                     .format(self.cur_maturity_pass, dispatcher_info.entry_block.serial))
            # During the previous step we changed dispatcher entry block fathers, so we need to reload them
            dispatcher_father_list = [self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset]
            nb_flattened_branches = 0
            for dispatcher_father in dispatcher_father_list:
                try:
                    nb_flattened_branches += self.resolve_dispatcher_father(dispatcher_father, dispatcher_info)
                except NotResolvableFatherException as e:
                    unflat_logger.warning(e)
                    pass
            dump_microcode_for_debug(self.mba, self.log_dir, "unflat_{0}_dispatcher_{1}_after_unflattening"
                                     .format(self.cur_maturity_pass, dispatcher_info.entry_block.serial))

        unflat_logger.info("Unflattening removed {0} branch".format(nb_flattened_branches))
        total_nb_change += nb_flattened_branches
        return total_nb_change

    def optimize(self, blk: mblock_t) -> int:
        self.mba = blk.mba
        if not self.check_if_rule_should_be_used(blk):
            return 0
        self.last_pass_nb_patch_done = 0
        unflat_logger.info("Unflattening at maturity {0} path {1}".format(self.cur_maturity, self.cur_maturity_pass))
        dump_microcode_for_debug(self.mba, self.log_dir, "unflat_{0}_start".format(self.cur_maturity_pass))
        self.retrieve_all_dispatchers()
        if len(self.dispatcher_list) == 0:
            unflat_logger.info("No dispatcher found at maturity {0}".format(self.mba.maturity))
            return 0
        else:
            unflat_logger.info("Unflattening: {0} dispatcher(s) found".format(len(self.dispatcher_list)))
            for dispatcher_info in self.dispatcher_list:
                dispatcher_info.print_info()
            self.last_pass_nb_patch_done = self.remove_flattening()
        unflat_logger.info("Unflattening at maturity {0} path {1}: {2} changes"
                           .format(self.cur_maturity, self.cur_maturity_pass, self.last_pass_nb_patch_done))
        nb_clean = mba_deep_cleaning(self.mba)
        dump_microcode_for_debug(self.mba, self.log_dir, "unflat_{0}_after_cleaning".format(self.cur_maturity_pass))
        if self.last_pass_nb_patch_done + nb_clean > 0:
            self.mba.mark_chains_dirty()
            self.mba.optimize_local(0)
            self.mba.verify(True)
        return self.last_pass_nb_patch_done

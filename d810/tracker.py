from __future__ import annotations
import logging
from typing import List, Union, Tuple, Dict
from ida_hexrays import *

from d810.emulator import MicroCodeEnvironment, MicroCodeInterpreter
from d810.cfg_utils import change_1way_block_successor, change_2way_block_conditional_successor, duplicate_block
from d810.hexrays_hooks import InstructionDefUseCollector
from d810.hexrays_helpers import equal_mops_ignore_size, get_mop_index, get_blk_index
from d810.hexrays_formatters import format_minsn_t, format_mop_t

# This module can be use to find the instruction that define the value of a mop. Basically, you:
# 1 - Create a MopTracker object with the list of mops to search
# 2 - Call search_backward while specifying the instruction where the search should start
# It will return a list if MopHistory, each MopHistory object of this list:
# * Represents one possible path to compute the searched mops
# * Stores all instructions used to compute the searched mops
#
# You can get the value of one of the searched mop by calling the get_mop_constant_value API of a MopHistory object.
# Behind the scene, it will emulate all microcode instructions on the MopHistory path.
#
# Finally the duplicate_histories API can be used to duplicate microcode blocks so that for each microcode block,
# the searched mops have only one possible values. For instance, this is a preliminary step used in code unflattening.


logger = logging.getLogger('D810.tracker')


class BlockInfo(object):
    def __init__(self, blk: mblock_t, ins=None):
        self.blk = blk
        self.ins_list = []
        if ins is not None:
            self.ins_list.append(ins)

    def get_copy(self) -> BlockInfo:
        new_block_info = BlockInfo(self.blk)
        new_block_info.ins_list = [x for x in self.ins_list]
        return new_block_info


class MopHistory(object):
    def __init__(self, searched_mop_list: List[mop_t]):
        self.searched_mop_list = [mop_t(x) for x in searched_mop_list]
        self.history = []
        self.unresolved_mop_list = []

        self._mc_interpreter = MicroCodeInterpreter()
        self._mc_initial_environment = MicroCodeEnvironment()
        self._mc_current_environment = self._mc_initial_environment.get_copy()
        self._is_dirty = True

    def add_mop_initial_value(self, mop: mop_t, value: int):
        self._is_dirty = True
        self._mc_initial_environment.define(mop, value)

    def get_copy(self) -> MopHistory:
        new_mop_history = MopHistory(self.searched_mop_list)
        new_mop_history.history = [x.get_copy() for x in self.history]
        new_mop_history.unresolved_mop_list = [x for x in self.unresolved_mop_list]
        new_mop_history._mc_initial_environment = self._mc_initial_environment.get_copy()
        new_mop_history._mc_current_environment = new_mop_history._mc_initial_environment.get_copy()
        return new_mop_history

    def is_resolved(self) -> bool:
        if len(self.unresolved_mop_list) == 0:
            return True
        for x in self.unresolved_mop_list:
            x_value = self._mc_initial_environment.lookup(x, raise_exception=False)
            if x_value is None:
                return False
        return True

    @property
    def block_path(self) -> List[mblock_t]:
        return [blk_info.blk for blk_info in self.history]

    @property
    def block_serial_path(self) -> List[int]:
        return [blk.serial for blk in self.block_path]

    def replace_block_in_path(self, old_blk: mblock_t, new_blk: mblock_t) -> bool:
        blk_index = get_blk_index(old_blk, self.block_path)
        if blk_index > 0:
            self.history[blk_index].blk = new_blk
            self._is_dirty = True
            return True
        else:
            logger.error("replace_block_in_path: should not happen")
            return False

    def insert_block_in_path(self, blk: mblock_t, where_index: int):
        self.history = self.history[:where_index] + [BlockInfo(blk)] + self.history[where_index:]
        self._is_dirty = True

    def insert_ins_in_block(self, blk: mblock_t, ins: minsn_t, before=True):
        blk_index = get_blk_index(blk, self.block_path)
        if blk_index < 0:
            return False
        blk_info = self.history[blk_index]
        if before:
            blk_info.ins_list = [ins] + blk_info.ins_list
        else:
            blk_info.ins_list = blk_info.ins_list + [ins]
        self._is_dirty = True

    def _execute_microcode(self) -> bool:
        if not self._is_dirty:
            return True
        formatted_mop_searched_list = "['" + "', '".join([format_mop_t(x) for x in self.searched_mop_list]) + "']"
        logger.debug("Computing: {0} for path {1}".format(formatted_mop_searched_list, self.block_serial_path))
        self._mc_current_environment = self._mc_initial_environment.get_copy()
        for blk_info in self.history:
            for blk_ins in blk_info.ins_list:
                logger.debug("Executing: {0}.{1}".format(blk_info.blk.serial, format_minsn_t(blk_ins)))
                if not self._mc_interpreter.eval_instruction(blk_info.blk, blk_ins, self._mc_current_environment):
                    self._is_dirty = False
                    return False
        self._is_dirty = False
        return True

    def get_mop_constant_value(self, searched_mop: mop_t) -> Union[None, int]:
        if not self._execute_microcode():
            return None
        return self._mc_interpreter.eval_mop(searched_mop, self._mc_current_environment)

    def print_info(self, detailed_info=False):
        formatted_mop_searched_list = [format_mop_t(x) for x in self.searched_mop_list]
        tmp = ", ".join(["{0}={1}".format(formatted_mop, self.get_mop_constant_value(mop))
                         for formatted_mop, mop in zip(formatted_mop_searched_list, self.searched_mop_list)])
        logger.info("MopHistory: resolved={0}, path={1}, mops={2}"
                    .format(self.is_resolved(), self.block_serial_path, tmp))
        if detailed_info:
            str_mop_list = "['" + "', '".join(formatted_mop_searched_list) + "']"
            if len(self.block_path) == 0:
                logger.info("MopHistory for {0} => nothing".format(str_mop_list))
                return

            end_blk = self.block_path[-1]
            end_ins = end_blk.tail
            if self.history[-1].ins_list:
                end_ins = self.history[-1].ins_list[-1]

            if end_ins:
                logger.info("MopHistory for {0} {1}.{2}".format(str_mop_list, end_blk.serial, format_minsn_t(end_ins)))
            else:
                logger.info("MopHistory for '{0}' {1}.tail".format(str_mop_list, end_blk.serial))
            logger.info("  path {0}".format(self.block_serial_path))
            for blk_info in self.history:
                for blk_ins in blk_info.ins_list:
                    logger.info("   {0}.{1}".format(blk_info.blk.serial, format_minsn_t(blk_ins)))


def get_standard_and_memory_mop_lists(mop_in: mop_t) -> Tuple[List[mop_t], List[mop_t]]:
    if mop_in.t in [mop_r, mop_S]:
        return [mop_in], []
    elif mop_in.t == mop_v:
        return [], [mop_in]
    elif mop_in.t == mop_d:
        ins_mop_info = InstructionDefUseCollector()
        mop_in.d.for_all_ops(ins_mop_info)
        return remove_segment_registers(ins_mop_info.unresolved_ins_mops), ins_mop_info.memory_unresolved_ins_mops
    else:
        logger.warning("Calling get_standard_and_memory_mop_lists with unsupported mop type {0}: '{1}'"
                       .format(mop_in.t, format_mop_t(mop_in)))
        return [], []


# A MopTracker will create new MopTracker to recursively track variable when multiple paths are possible,
# The cur_mop_tracker_nb_path global variable is used to limit the number of MopTracker created
cur_mop_tracker_nb_path = 0


class MopTracker(object):
    def __init__(self, searched_mop_list: List[mop_t], max_nb_block=-1, max_path=-1):
        self.mba = None
        self._unresolved_mops = []
        self._memory_unresolved_mops = []
        for searched_mop in searched_mop_list:
            a, b = get_standard_and_memory_mop_lists(searched_mop)
            self._unresolved_mops += a
            self._memory_unresolved_mops += b
        self.history = MopHistory(searched_mop_list)
        self.max_nb_block = max_nb_block
        self.max_path = max_path
        self.avoid_list = []
        self.call_detected = False
        self.constant_mops = []

    @staticmethod
    def reset():
        global cur_mop_tracker_nb_path
        cur_mop_tracker_nb_path = 0

    def add_mop_definition(self, mop: mop_t, cst_value: int):
        self.constant_mops.append([mop, cst_value])
        self.history.add_mop_initial_value(mop, cst_value)

    def get_copy(self) -> MopTracker:
        global cur_mop_tracker_nb_path
        new_mop_tracker = MopTracker(self._unresolved_mops, self.max_nb_block, self.max_path)
        new_mop_tracker._memory_unresolved_mops = [x for x in self._memory_unresolved_mops]
        new_mop_tracker.constant_mops = [[x[0], x[1]] for x in self.constant_mops]
        new_mop_tracker.history = self.history.get_copy()
        cur_mop_tracker_nb_path += 1
        return new_mop_tracker

    def search_backward(self, blk: mblock_t, ins: minsn_t, avoid_list=None, must_use_pred=None,
                        stop_at_first_duplication=False) -> List[MopHistory]:
        logger.debug("Searching backward (reg): {0}".format([format_mop_t(x) for x in self._unresolved_mops]))
        logger.debug("Searching backward (mem): {0}".format([format_mop_t(x) for x in self._memory_unresolved_mops]))
        logger.debug("Searching backward (cst): {0}"
                     .format(["{0}: {1:x}".format(format_mop_t(x[0]), x[1]) for x in self.constant_mops]))
        self.mba = blk.mba
        self.avoid_list = avoid_list if avoid_list else []
        blk_with_multiple_pred = self.search_until_multiple_predecessor(blk, ins)
        if self.is_resolved():
            logger.debug("MopTracker is resolved:  {0}".format(self.history.block_serial_path))
            self.history.unresolved_mop_list = [x for x in self._unresolved_mops]
            return [self.history]
        elif blk_with_multiple_pred is None:
            logger.debug("MopTracker unresolved: (blk_with_multiple_pred): {0}".format(self.history.block_serial_path))
            self.history.unresolved_mop_list = [x for x in self._unresolved_mops]
            return [self.history]
        elif self.max_nb_block != -1 and len(self.history.block_serial_path) > self.max_nb_block:
            logger.debug("MopTracker unresolved: (max_nb_block): {0}".format(self.history.block_serial_path))
            self.history.unresolved_mop_list = [x for x in self._unresolved_mops]
            return [self.history]
        elif self.max_path != -1 and cur_mop_tracker_nb_path > self.max_path:
            logger.debug("MopTracker unresolved: (max_path: {0}".format(cur_mop_tracker_nb_path))
            self.history.unresolved_mop_list = [x for x in self._unresolved_mops]
            return [self.history]
        elif self.call_detected:
            logger.debug("MopTracker unresolved: (call): {0}".format(self.history.block_serial_path))
            self.history.unresolved_mop_list = [x for x in self._unresolved_mops]
            return [self.history]

        if stop_at_first_duplication:
            self.history.unresolved_mop_list = [x for x in self._unresolved_mops]
            return [self.history]
        logger.debug("MopTracker creating child because multiple pred: {0}".format(self.history.block_serial_path))
        possible_histories = []
        if must_use_pred is not None and must_use_pred.serial in blk_with_multiple_pred.predset:
            new_tracker = self.get_copy()
            possible_histories += new_tracker.search_backward(must_use_pred, None, self.avoid_list, must_use_pred)
        else:
            for blk_pred_serial in blk_with_multiple_pred.predset:
                new_tracker = self.get_copy()
                possible_histories += new_tracker.search_backward(self.mba.get_mblock(blk_pred_serial), None,
                                                                  self.avoid_list, must_use_pred)
        return possible_histories

    def search_until_multiple_predecessor(self, blk: mblock_t, ins: Union[None, minsn_t] = None) -> Union[None, mblock_t]:
        # By default, we start searching from block tail
        cur_ins = ins if ins else blk.tail
        cur_blk = blk

        while not self.is_resolved():
            # Explore one block
            if cur_blk.serial in self.history.block_serial_path:
                self.history.insert_block_in_path(cur_blk, 0)
                return None
            if cur_blk.serial in self.avoid_list:
                self.history.insert_block_in_path(cur_blk, 0)
                return None
            self.history.insert_block_in_path(cur_blk, 0)
            cur_ins = self.blk_find_def_backward(cur_blk, cur_ins)
            while cur_ins:
                cur_ins = self.blk_find_def_backward(cur_blk, cur_ins)
            if cur_blk.npred() > 1:
                return cur_blk
            elif cur_blk.npred() == 0:
                return None
            else:
                cur_blk = self.mba.get_mblock(cur_blk.predset[0])
                cur_ins = cur_blk.tail

        # We want to handle cases where the self.is_resolved() is True without doing anything
        if len(self.history.block_serial_path) == 0:
            self.history.insert_block_in_path(cur_blk, 0)
        return None

    def is_resolved(self) -> bool:
        if (len(self._unresolved_mops) == 0) and (len(self._memory_unresolved_mops) == 0):
            return True

        for x in self._unresolved_mops:
            x_index = get_mop_index(x, [y[0] for y in self.constant_mops])
            if x_index == -1:
                return False
        return True

    def _build_ml_list(self, blk: mblock_t) -> Union[None, mlist_t]:
        ml = mlist_t()
        for unresolved_mop in self._unresolved_mops:
            if unresolved_mop.t not in [mop_r, mop_S]:
                logger.warning("_build_ml_list: Not supported mop type '{0}'".format(unresolved_mop.t))
                return None
            blk.append_use_list(ml, unresolved_mop, MUST_ACCESS)
        return ml

    def blk_find_def_backward(self, blk: mblock_t, ins_start: minsn_t) -> Union[None, minsn_t]:
        if self.is_resolved():
            return None
        ml = self._build_ml_list(blk)
        if not ml:
            logger.warning("blk_find_def_backward: _build_ml_list failed")
            return None
        ins_def = self._blk_find_ins_def_backward(blk, ins_start, ml)
        if ins_def:
            is_ok = self.update_history(blk, ins_def)
            if not is_ok:
                return None
            ins_def = ins_def.prev
        return ins_def

    def update_history(self, blk: mblock_t, ins_def: minsn_t) -> bool:
        logger.debug("Updating history with {0}.{1}".format(blk.serial, format_minsn_t(ins_def)))
        self.history.insert_ins_in_block(blk, ins_def, before=True)
        if ins_def.opcode == m_call:
            self.call_detected = True
            return False
        ins_mop_info = InstructionDefUseCollector()
        ins_def.for_all_ops(ins_mop_info)

        for target_mop in ins_mop_info.target_mops:
            resolved_mop_index = get_mop_index(target_mop, self._unresolved_mops)
            if resolved_mop_index != -1:
                logger.debug("Removing {0} from unresolved mop".format(format_mop_t(target_mop)))
                self._unresolved_mops.pop(resolved_mop_index)
        cleaned_unresolved_ins_mops = remove_segment_registers(ins_mop_info.unresolved_ins_mops)
        for ins_def_mop in cleaned_unresolved_ins_mops:
            ins_def_mop_index = get_mop_index(ins_def_mop, self._unresolved_mops)
            if ins_def_mop_index == -1:
                logger.debug("Adding {0} in unresolved mop".format(format_mop_t(ins_def_mop)))
                self._unresolved_mops.append(ins_def_mop)

        for target_mop in ins_mop_info.target_mops:
            resolved_mop_index = get_mop_index(target_mop, self._memory_unresolved_mops)
            if resolved_mop_index != -1:
                logger.debug("Removing {0} from memory unresolved mop".format(format_mop_t(target_mop)))
                self._memory_unresolved_mops.pop(resolved_mop_index)
        for ins_def_mem_mop in ins_mop_info.memory_unresolved_ins_mops:
            ins_def_mop_index = get_mop_index(ins_def_mem_mop, self._memory_unresolved_mops)
            if ins_def_mop_index == -1:
                logger.debug("Adding {0} in memory unresolved mop".format(format_mop_t(ins_def_mem_mop)))
                self._memory_unresolved_mops.append(ins_def_mem_mop)
        return True

    def _blk_find_ins_def_backward(self, blk: mblock_t, ins_start: minsn_t, ml: mlist_t) -> Union[None, minsn_t]:
        cur_ins = ins_start
        while cur_ins is not None:
            def_list = blk.build_def_list(cur_ins, MAY_ACCESS | FULL_XDSU)
            if ml.has_common(def_list):
                return cur_ins
            for mem_mop in self._memory_unresolved_mops:
                if equal_mops_ignore_size(cur_ins.d, mem_mop):
                    return cur_ins
            cur_ins = cur_ins.prev
        return None


def get_block_with_multiple_predecessors(var_histories: List[MopHistory]) -> Tuple[Union[None, mblock_t],
                                                                                   Union[None, Dict[int, List[MopHistory]]]]:
    for i, var_history in enumerate(var_histories):
        pred_blk = var_history.block_path[0]
        for block in var_history.block_path[1:]:
            tmp_dict = {pred_blk.serial: [var_history]}
            for j in range(i + 1, len(var_histories)):
                blk_index = get_blk_index(block, var_histories[j].block_path)
                if (blk_index - 1) >= 0:
                    other_pred = var_histories[j].block_path[blk_index - 1]
                    if other_pred.serial not in tmp_dict.keys():
                        tmp_dict[other_pred.serial] = []
                    tmp_dict[other_pred.serial].append(var_histories[j])
            if len(tmp_dict) > 1:
                return block, tmp_dict
            pred_blk = block
    return None, None


def try_to_duplicate_one_block(var_histories: List[MopHistory]) -> Tuple[int, int]:
    nb_duplication = 0
    nb_change = 0
    if (len(var_histories) == 0) or (len(var_histories[0].block_path) == 0):
        return nb_duplication, nb_change
    mba = var_histories[0].block_path[0].mba
    block_to_duplicate, pred_dict = get_block_with_multiple_predecessors(var_histories)
    if block_to_duplicate is None:
        return nb_duplication, nb_change
    logger.debug("Block to duplicate found: {0} with {1} successors"
                 .format(block_to_duplicate.serial, block_to_duplicate.nsucc()))
    i = 0
    for pred_serial, pred_history_group in pred_dict.items():
        # We do not duplicate first group
        if i >= 1:
            logger.debug("  Before {0}: {1}"
                         .format(pred_serial, [var_history.block_serial_path for var_history in pred_history_group]))
            pred_block = mba.get_mblock(pred_serial)
            duplicated_blk_jmp, duplicated_blk_default = duplicate_block(block_to_duplicate)
            nb_duplication += 1 if duplicated_blk_jmp is not None else 0
            nb_duplication += 1 if duplicated_blk_default is not None else 0
            logger.debug("  Making {0} goto {1}".format(pred_block.serial, duplicated_blk_jmp.serial))
            if (pred_block.tail is None) or (not is_mcode_jcond(pred_block.tail.opcode)):
                change_1way_block_successor(pred_block, duplicated_blk_jmp.serial)
                nb_change += 1
            else:
                if block_to_duplicate.serial == pred_block.tail.d.b:
                    change_2way_block_conditional_successor(pred_block, duplicated_blk_jmp.serial)
                    nb_change += 1
                else:
                    logger.warning(" not sure this is suppose to happen")
                    change_1way_block_successor(pred_block.mba.get_mblock(pred_block.serial + 1),
                                                duplicated_blk_jmp.serial)
                    nb_change += 1

            block_to_duplicate_default_successor = mba.get_mblock(block_to_duplicate.serial + 1)
            logger.debug("  Now, we fix var histories...")
            for var_history in pred_history_group:
                var_history.replace_block_in_path(block_to_duplicate, duplicated_blk_jmp)
                if block_to_duplicate.tail is not None and is_mcode_jcond(block_to_duplicate.tail.opcode):
                    index_jump_block = get_blk_index(duplicated_blk_jmp, var_history.block_path)
                    if index_jump_block + 1 < len(var_history.block_path):
                        original_jump_block_successor = var_history.block_path[index_jump_block + 1]
                        if original_jump_block_successor.serial == block_to_duplicate_default_successor.serial:
                            var_history.insert_block_in_path(duplicated_blk_default, index_jump_block + 1)
        i += 1
        logger.debug("  After {0}: {1}"
                     .format(pred_serial, [var_history.block_serial_path for var_history in pred_history_group]))
    for i, var_history in enumerate(var_histories):
        logger.debug(" internal_pass_end.{0}: {1}".format(i, var_history.block_serial_path))
    return nb_duplication, nb_change


def duplicate_histories(var_histories: List[MopHistory], max_nb_pass: int = 10) -> Tuple[int, int]:
    cur_pass = 0
    total_nb_duplication = 0
    total_nb_change = 0
    logger.info("Trying to fix new var_history...")
    for i, var_history in enumerate(var_histories):
        logger.info(" start.{0}: {1}".format(i, var_history.block_serial_path))
    while cur_pass < max_nb_pass:
        logger.debug("Current path {0}".format(cur_pass))
        nb_duplication, nb_change = try_to_duplicate_one_block(var_histories)
        if nb_change == 0 and nb_duplication == 0:
            break
        total_nb_duplication += nb_duplication
        total_nb_change += nb_change
        cur_pass += 1
    for i, var_history in enumerate(var_histories):
        logger.info(" end.{0}: {1}".format(i, var_history.block_serial_path))
    return total_nb_duplication, total_nb_change


def get_segment_register_indexes(mop_list: List[mop_t]) -> List[int]:
    # This is a very dirty and probably buggy
    segment_register_indexes = []
    for i, mop in enumerate(mop_list):
        if mop.t == mop_r:
            formatted_mop = format_mop_t(mop)
            if formatted_mop in ["ds.2", "cs.2", "es.2", "ss.2"]:
                segment_register_indexes.append(i)
    return segment_register_indexes


def remove_segment_registers(mop_list: List[mop_t]) -> List[mop_t]:
    # TODO: instead of doing that, we should add the segment registers to the (global?) emulation environment
    segment_register_indexes = get_segment_register_indexes(mop_list)
    if len(segment_register_indexes) == 0:
        return mop_list
    new_mop_list = []
    for i, mop in enumerate(mop_list):
        if i in segment_register_indexes:
            pass
        else:
            new_mop_list.append(mop)
    return new_mop_list

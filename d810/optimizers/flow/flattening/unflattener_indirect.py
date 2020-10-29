import logging
import idaapi
from typing import List
from ida_hexrays import *

from d810.hexrays_helpers import append_mop_if_not_in_list, AND_TABLE, CONTROL_FLOW_OPCODES
from d810.tracker import MopTracker, MopHistory
from d810.optimizers.flow.flattening.generic import GenericDispatcherBlockInfo, GenericDispatcherInfo, \
    GenericDispatcherCollector, GenericDispatcherUnflatteningRule, NotDuplicableFatherException, DispatcherUnflatteningException, NotResolvableFatherException
from d810.optimizers.flow.flattening.utils import configure_mop_tracker_log_verbosity, restore_mop_tracker_log_verbosity
from d810.tracker import duplicate_histories
from d810.cfg_utils import create_block, change_1way_block_successor
from d810.hexrays_formatters import format_minsn_t, format_mop_t
from d810.emulator import MicroCodeEnvironment, MicroCodeInterpreter

unflat_logger = logging.getLogger('D810.unflat')
FLATTENING_JUMP_OPCODES = [m_jtbl]


class TigressIndirectDispatcherBlockInfo(GenericDispatcherBlockInfo):
    pass


class TigressIndirectDispatcherInfo(GenericDispatcherInfo):
    def explore(self, blk: mblock_t):
        self.reset()
        if not self._is_candidate_for_dispatcher_entry_block(blk):
            return
        self.mop_compared = self._get_comparison_info(blk)
        self.entry_block = TigressIndirectDispatcherBlockInfo(blk)
        self.entry_block.parse()
        for used_mop in self.entry_block.use_list:
            append_mop_if_not_in_list(used_mop, self.entry_block.assume_def_list)
        self.dispatcher_internal_blocks.append(self.entry_block)

        self.dispatcher_exit_blocks = []
        self.comparison_values = []
        return True

    def _get_comparison_info(self, blk: mblock_t):
        # blk.tail must be a jtbl
        if (blk.tail is None) or (blk.tail.opcode != m_ijmp):
            return None, None
        return blk.tail.l

    def _is_candidate_for_dispatcher_entry_block(self, blk: mblock_t):
        if (blk.tail is None) or (blk.tail.opcode != m_ijmp):
            return False
        return True

    def should_emulation_continue(self, cur_blk: mblock_t):
        if (cur_blk is not None) and (cur_blk.serial == self.entry_block.serial):
            return True
        return False


class TigressIndirectDispatcherCollector(GenericDispatcherCollector):
    DISPATCHER_CLASS = TigressIndirectDispatcherInfo
    DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK = 0
    DEFAULT_DISPATCHER_MIN_EXIT_BLOCK = 0
    DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE = 0


class LabelTableInfo(object):
    def __init__(self, sp_offset, mem_offset, nb_elt):
        self.sp_offset = sp_offset
        self.mem_offset = mem_offset
        self.nb_elt = nb_elt

    def update_mop_tracker(self, mba: mbl_array_t, mop_tracker: MopTracker):
        stack_array_base_address = mba.stkoff_ida2vd(self.sp_offset)
        # print("stack_array_base_address: {0:x}".format(stack_array_base_address))
        for i in range(self.nb_elt):
            tmp_mop = mop_t()
            tmp_mop.erase()
            tmp_mop._make_stkvar(mba, stack_array_base_address + 8 * i)
            tmp_mop.size = 8
            mem_val = idaapi.get_qword(self.mem_offset + 8 * i) & AND_TABLE[8]
            mop_tracker.add_mop_definition(tmp_mop, mem_val)


class UnflattenerTigressIndirect(GenericDispatcherUnflatteningRule):
    DESCRIPTION = ""
    DISPATCHER_COLLECTOR_CLASS = TigressIndirectDispatcherCollector
    DEFAULT_UNFLATTENING_MATURITIES = [MMAT_LOCOPT]
    DEFAULT_MAX_DUPLICATION_PASSES = 20
    DEFAULT_MAX_PASSES = 1

    def __init__(self):
        super().__init__()
        self.label_info = None
        self.goto_table_info = {}

    def configure(self, kwargs):
        super().configure(kwargs)
        if "goto_table_info" in self.config.keys():
            for ea_str, table_info in self.config["goto_table_info"].items():
                self.goto_table_info[int(ea_str, 16)] = LabelTableInfo(sp_offset=int(table_info["stack_table_offset"], 16),
                                                                       mem_offset=int(table_info["table_address"], 16),
                                                                       nb_elt=table_info["table_nb_elt"])

    def check_if_rule_should_be_used(self, blk: mblock_t):
        if not super().check_if_rule_should_be_used(blk):
            return False
        if self.mba.entry_ea not in self.goto_table_info:
            return False
        if (self.cur_maturity_pass >= 1) and (self.last_pass_nb_patch_done == 0):
            return False
        self.label_info = self.goto_table_info[self.mba.entry_ea]
        return True

    def register_initialization_variables(self, mop_tracker: MopTracker):
        self.label_info.update_mop_tracker(self.mba, mop_tracker)

    def check_if_histories_are_resolved(self, mop_histories: List[MopHistory]):
        return True

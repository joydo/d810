import logging
from typing import List, Tuple
from ida_hexrays import *

from d810.tracker import MopTracker
from d810.cfg_utils import duplicate_block, make_2way_block_goto, update_blk_successor

from d810.hexrays_formatters import format_minsn_t, dump_microcode_for_debug
from d810.optimizers.flow.flattening.utils import get_all_possibles_values
from d810.optimizers.flow.flattening.generic import GenericUnflatteningRule
from d810.utils import unsigned_to_signed


unflat_logger = logging.getLogger('D810.unflat')

JMP_OPCODE_HANDLED = [m_jnz, m_jz, m_jae, m_jb, m_ja, m_jbe, m_jge, m_jg, m_jl, m_jle]


class FixPredecessorOfConditionalJumpBlock(GenericUnflatteningRule):
    DESCRIPTION = "Detect if a predecessor of a conditional block always takes the same path and patch it (works for O-LLVM style control flow flattening)"
    DEFAULT_UNFLATTENING_MATURITIES = [MMAT_CALLS, MMAT_GLBOPT1, MMAT_GLBOPT2]
    DEFAULT_MAX_PASSES = 100

    def is_jump_taken(self, jmp_blk: mblock_t, pred_comparison_values: List[int]) -> Tuple[bool, bool]:
        if len(pred_comparison_values) == 0:
            return False, False
        jmp_ins = jmp_blk.tail
        compared_value = jmp_ins.r.nnn.value
        compared_value_size = jmp_ins.r.size
        is_jmp_always_taken = False
        is_jmp_never_taken = False
        if jmp_ins.opcode == m_jnz:
            is_jmp_always_taken = all([possible_value != compared_value for possible_value in pred_comparison_values])
            is_jmp_never_taken = all([possible_value == compared_value for possible_value in pred_comparison_values])
        elif jmp_ins.opcode == m_jz:
            is_jmp_always_taken = all([possible_value == compared_value for possible_value in pred_comparison_values])
            is_jmp_never_taken = all([possible_value != compared_value for possible_value in pred_comparison_values])
        elif jmp_ins.opcode == m_jae:
            is_jmp_always_taken = all([possible_value >= compared_value for possible_value in pred_comparison_values])
            is_jmp_never_taken = all([possible_value < compared_value for possible_value in pred_comparison_values])
        elif jmp_ins.opcode == m_jb:
            is_jmp_always_taken = all([possible_value < compared_value for possible_value in pred_comparison_values])
            is_jmp_never_taken = all([possible_value >= compared_value for possible_value in pred_comparison_values])
        elif jmp_ins.opcode == m_ja:
            is_jmp_always_taken = all([possible_value > compared_value for possible_value in pred_comparison_values])
            is_jmp_never_taken = all([possible_value <= compared_value for possible_value in pred_comparison_values])
        elif jmp_ins.opcode == m_jbe:
            is_jmp_always_taken = all([unsigned_to_signed(possible_value, compared_value_size) > unsigned_to_signed(
                compared_value, compared_value_size) for possible_value in pred_comparison_values])
            is_jmp_never_taken = all([unsigned_to_signed(possible_value, compared_value_size) <= unsigned_to_signed(
                compared_value, compared_value_size) for possible_value in pred_comparison_values])
        elif jmp_ins.opcode == m_jg:
            is_jmp_always_taken = all([unsigned_to_signed(possible_value, compared_value_size) > unsigned_to_signed(
                compared_value, compared_value_size) for possible_value in pred_comparison_values])
            is_jmp_never_taken = all([unsigned_to_signed(possible_value, compared_value_size) <= unsigned_to_signed(
                compared_value, compared_value_size) for possible_value in pred_comparison_values])
        elif jmp_ins.opcode == m_jge:
            is_jmp_always_taken = all([unsigned_to_signed(possible_value, compared_value_size) >= unsigned_to_signed(
                compared_value, compared_value_size) for possible_value in pred_comparison_values])
            is_jmp_never_taken = all([unsigned_to_signed(possible_value, compared_value_size) < unsigned_to_signed(
                compared_value, compared_value_size) for possible_value in pred_comparison_values])
        elif jmp_ins.opcode == m_jl:
            is_jmp_always_taken = all([unsigned_to_signed(possible_value, compared_value_size) < unsigned_to_signed(
                compared_value, compared_value_size) for possible_value in pred_comparison_values])
            is_jmp_never_taken = all([unsigned_to_signed(possible_value, compared_value_size) >= unsigned_to_signed(
                compared_value, compared_value_size) for possible_value in pred_comparison_values])
        elif jmp_ins.opcode == m_jle:
            is_jmp_always_taken = all([unsigned_to_signed(possible_value, compared_value_size) <= unsigned_to_signed(
                compared_value, compared_value_size) for possible_value in pred_comparison_values])
            is_jmp_never_taken = all([unsigned_to_signed(possible_value, compared_value_size) > unsigned_to_signed(
                compared_value, compared_value_size) for possible_value in pred_comparison_values])
        return is_jmp_always_taken, is_jmp_never_taken

    def sort_predecessors(self, blk):
        # this function sorts the blk predecessors into three list:
        # - A list of predecessors where the jump is always taken
        # - A list of predecessors where the jump is never taken
        # - A list of predecessors where we don't know
        pred_jmp_always_taken = []
        pred_jmp_never_taken = []
        pred_jmp_unk = []
        op_compared = mop_t(blk.tail.l)
        blk_preset_list = [x for x in blk.predset]
        for pred_serial in blk_preset_list:
            cmp_variable_tracker = MopTracker([op_compared], max_nb_block=100, max_path=1000)
            cmp_variable_tracker.reset()
            pred_blk = blk.mba.get_mblock(pred_serial)
            pred_histories = cmp_variable_tracker.search_backward(pred_blk, pred_blk.tail)
            pred_values = get_all_possibles_values(pred_histories, [op_compared])
            pred_values = [x[0] for x in pred_values]
            unflat_logger.info("Pred {0} has {1} possible path ({2} different cst): {3}"
                               .format(pred_blk.serial, len(pred_values), len(set(pred_values)), pred_values))
            if None in pred_values:
                pred_jmp_unk.append(pred_blk)
                continue
            is_jmp_always_taken, is_jmp_never_taken = self.is_jump_taken(blk, pred_values)
            if is_jmp_always_taken and is_jmp_never_taken:
                # this should never happen
                unflat_logger.error("It seems that I am stupid: '{0}' is always taken and not taken when coming from {1}: {2}".format(format_minsn_t(blk.tail), pred_blk.serial, pred_values))
                pred_jmp_unk.append(pred_blk)
                continue
            if is_jmp_always_taken:
                unflat_logger.info("It seems that '{0}' is always taken when coming from {1}: {2}".format(format_minsn_t(blk.tail), pred_blk.serial, pred_values))
                pred_jmp_always_taken.append(pred_blk)
            if is_jmp_never_taken:
                unflat_logger.info("It seems that '{0}' is never taken when coming from {1}: {2}".format(format_minsn_t(blk.tail), pred_blk.serial, pred_values))
                pred_jmp_never_taken.append(pred_blk)
        return pred_jmp_always_taken, pred_jmp_never_taken, pred_jmp_unk

    def analyze_blk(self, blk: mblock_t) -> int:
        if (blk.tail is None) or blk.tail.opcode not in JMP_OPCODE_HANDLED:
            return 0
        if blk.tail.r.t != mop_n:
            return 0
        unflat_logger.info("Checking if block {0} can be simplified: {1}".format(blk.serial, format_minsn_t(blk.tail)))
        pred_jmp_always_taken, pred_jmp_never_taken, pred_jmp_unk = self.sort_predecessors(blk)
        unflat_logger.info("Block {0} has {1} preds: {2} always jmp, {3} never jmp, {4} unk".format(blk.serial, blk.npred(), len(pred_jmp_always_taken), len(pred_jmp_never_taken), len(pred_jmp_unk)))
        nb_change = 0
        if len(pred_jmp_always_taken) > 0:
            dump_microcode_for_debug(self.mba, self.log_dir, "{0}_{1}_before_jmp_always_fix".format(self.cur_maturity_pass, blk.serial))
            for pred_blk in pred_jmp_always_taken:
                new_jmp_block, new_default_block = duplicate_block(blk)
                make_2way_block_goto(new_jmp_block, blk.tail.d.b)
                update_blk_successor(pred_blk, blk.serial, new_jmp_block.serial)
            dump_microcode_for_debug(self.mba, self.log_dir, "{0}_{1}_after_jmp_always_fix".format(self.cur_maturity_pass, blk.serial))
            nb_change += len(pred_jmp_always_taken)
        if len(pred_jmp_never_taken) > 0:
            dump_microcode_for_debug(self.mba, self.log_dir, "{0}_{1}_before_jmp_never_fix".format(self.cur_maturity_pass, blk.serial))
            for pred_blk in pred_jmp_never_taken:
                new_jmp_block, new_default_block = duplicate_block(blk)
                make_2way_block_goto(new_jmp_block, blk.serial + 1)
                update_blk_successor(pred_blk, blk.serial, new_jmp_block.serial)
            dump_microcode_for_debug(self.mba, self.log_dir, "{0}_{1}_after_jmp_never_fix".format(self.cur_maturity_pass, blk.serial))
            nb_change += len(pred_jmp_never_taken)
        return nb_change

    def optimize(self, blk: mblock_t) -> int:
        self.mba = blk.mba
        if not self.check_if_rule_should_be_used(blk):
            return 0
        self.last_pass_nb_patch_done = self.analyze_blk(blk)
        if self.last_pass_nb_patch_done > 0:
            self.mba.mark_chains_dirty()
            self.mba.optimize_local(0)
            self.mba.verify(True)
        return self.last_pass_nb_patch_done

    def check_if_rule_should_be_used(self, blk: mblock_t) -> bool:
        if self.cur_maturity != self.mba.maturity:
            self.cur_maturity = self.mba.maturity
            self.cur_maturity_pass = 0
        if self.cur_maturity not in self.maturities:
            return False
        if (self.DEFAULT_MAX_PASSES is not None) and (self.cur_maturity_pass >= self.DEFAULT_MAX_PASSES):
            return False
        if (blk.tail is None) or blk.tail.opcode not in JMP_OPCODE_HANDLED:
            return False
        if blk.tail.r.t != mop_n:
            return False
        self.cur_maturity_pass += 1
        return True

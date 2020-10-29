import logging
from typing import List
from ida_hexrays import *

from d810.tracker import MopTracker
from d810.cfg_utils import change_1way_block_successor
from d810.hexrays_formatters import format_minsn_t, dump_microcode_for_debug
from d810.optimizers.flow.flattening.utils import get_all_possibles_values
from d810.optimizers.flow.flattening.generic import GenericUnflatteningRule

unflat_logger = logging.getLogger('D810.unflat')

FAKE_LOOP_OPCODES = [m_jz, m_jnz]


class UnflattenerFakeJump(GenericUnflatteningRule):
    DESCRIPTION = "Check if a jump is always taken for each father blocks and remove them"
    DEFAULT_UNFLATTENING_MATURITIES = [MMAT_CALLS, MMAT_GLBOPT1]
    DEFAULT_MAX_PASSES = None

    def analyze_blk(self, blk: mblock_t) -> int:
        if (blk.tail is None) or blk.tail.opcode not in FAKE_LOOP_OPCODES:
            return 0
        if blk.get_reginsn_qty() != 1:
            return 0
        if blk.tail.r.t != mop_n:
            return 0
        unflat_logger.info("Checking if block {0} is fake loop: {1}".format(blk.serial, format_minsn_t(blk.tail)))
        op_compared = mop_t(blk.tail.l)
        blk_preset_list = [x for x in blk.predset]
        nb_change = 0
        for pred_serial in blk_preset_list:
            cmp_variable_tracker = MopTracker([op_compared], max_nb_block=100, max_path=1000)
            cmp_variable_tracker.reset()
            pred_blk = blk.mba.get_mblock(pred_serial)
            pred_histories = cmp_variable_tracker.search_backward(pred_blk, pred_blk.tail)

            father_is_resolvable = all([father_history.is_resolved() for father_history in pred_histories])
            if not father_is_resolvable:
                return 0
            pred_values = get_all_possibles_values(pred_histories, [op_compared])
            pred_values = [x[0] for x in pred_values]
            if None in pred_values:
                unflat_logger.info("Some path are not resolved, can't fix jump")
                return 0
            unflat_logger.info("Pred {0} has {1} possible path ({2} different cst): {3}"
                               .format(pred_blk.serial, len(pred_values), len(set(pred_values)), pred_values))
            if self.fix_successor(blk, pred_blk, pred_values):
                nb_change += 1
        return nb_change

    def fix_successor(self, fake_loop_block: mblock_t, pred: mblock_t, pred_comparison_values: List[int]) -> bool:
        if len(pred_comparison_values) == 0:
            return False
        jmp_ins = fake_loop_block.tail
        compared_value = jmp_ins.r.nnn.value
        jmp_taken = False
        jmp_not_taken = False
        dst_serial = None
        if jmp_ins.opcode == m_jz:
            jmp_taken = all([possible_value == compared_value for possible_value in pred_comparison_values])

            jmp_not_taken = all([possible_value != compared_value for possible_value in pred_comparison_values])
        elif jmp_ins.opcode == m_jnz:
            jmp_taken = all([possible_value != compared_value for possible_value in pred_comparison_values])
            jmp_not_taken = all([possible_value == compared_value for possible_value in pred_comparison_values])
        # TODO: handles other jumps cases
        if jmp_taken:
            unflat_logger.info("It seems that '{0}' is always taken when coming from {1}: {2}"
                               .format(format_minsn_t(jmp_ins), pred.serial, pred_comparison_values))
            dst_serial = jmp_ins.d.b
        if jmp_not_taken:
            unflat_logger.info("It seems that '{0}' is never taken when coming from {1}: {2}"
                               .format(format_minsn_t(jmp_ins), pred.serial, pred_comparison_values))
            dst_serial = fake_loop_block.serial + 1
        if dst_serial is None:
            unflat_logger.debug("Jump seems legit '{0}' from {1}: {2}"
                                .format(format_minsn_t(jmp_ins), pred.serial, pred_comparison_values))
            return False
        dump_microcode_for_debug(self.mba, self.log_dir, "{0}_before_fake_jump".format(self.cur_maturity_pass))
        unflat_logger.info("Making pred {0} with value {1} goto {2} ({3})"
                           .format(pred.serial, pred_comparison_values, dst_serial, format_minsn_t(jmp_ins)))
        dump_microcode_for_debug(self.mba, self.log_dir, "{0}_after_fake_jump".format(self.cur_maturity_pass))
        return change_1way_block_successor(pred, dst_serial)

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

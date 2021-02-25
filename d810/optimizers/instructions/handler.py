from __future__ import annotations
import logging
from typing import List
from ida_hexrays import *

from d810.optimizers.handler import OptimizationRule
from d810.hexrays_formatters import format_minsn_t
from d810.ast import minsn_to_ast, AstNode
from d810.errors import D810Exception


d810_logger = logging.getLogger('D810')
optimizer_logger = logging.getLogger('D810.optimizer')


class InstructionOptimizationRule(OptimizationRule):
    def __init__(self):
        super().__init__()
        self.maturities = []

    def check_and_replace(self, blk, ins):
        return None


class GenericPatternRule(InstructionOptimizationRule):
    PATTERN = None
    PATTERNS = None
    REPLACEMENT_PATTERN = None

    def __init__(self):
        super().__init__()
        self.pattern_candidates = [self.PATTERN]
        if self.PATTERNS is not None:
            self.pattern_candidates += self.PATTERNS

    def check_candidate(self, candidate: AstNode):
        # Perform rule specific checks
        return False

    def get_valid_candidates(self, instruction: minsn_t, stop_early=True):
        valid_candidates = []
        tmp = minsn_to_ast(instruction)
        if tmp is None:
            return []
        for candidate_pattern in self.pattern_candidates:
            if not candidate_pattern.check_pattern_and_copy_mops(tmp):
                continue
            if not self.check_candidate(candidate_pattern):
                continue
            valid_candidates.append(candidate_pattern)
            if stop_early:
                return valid_candidates
        return []

    def get_replacement(self, candidate: AstNode):
        is_ok = self.REPLACEMENT_PATTERN.update_leafs_mop(candidate)
        if not is_ok:
            return None
        new_ins = self.REPLACEMENT_PATTERN.create_minsn(candidate.ea, candidate.dst_mop)
        return new_ins

    def check_and_replace(self, blk: mblock_t, instruction: minsn_t):
        valid_candidates = self.get_valid_candidates(instruction, stop_early=True)
        if len(valid_candidates) == 0:
            return None
        new_instruction = self.get_replacement(valid_candidates[0])
        return new_instruction

    @property
    def description(self):
        if self.DESCRIPTION is not None:
            return self.DESCRIPTION
        if (self.PATTERN is None) or (self.REPLACEMENT_PATTERN is None):
            return ""
        self.PATTERN.reset_mops()
        self.REPLACEMENT_PATTERN.reset_mops()
        return "{0} => {1}".format(self.PATTERN, self.REPLACEMENT_PATTERN)


class InstructionOptimizer(object):
    RULE_CLASSES = []
    NAME = None

    def __init__(self, maturities: List[int], log_dir=None):
        self.rules = set()
        self.rules_usage_info = {}
        self.maturities = maturities
        self.log_dir = log_dir
        self.cur_maturity = MMAT_PREOPTIMIZED

    def add_rule(self, rule: InstructionOptimizationRule):
        is_valid_rule_class = False
        for rule_class in self.RULE_CLASSES:
            if isinstance(rule, rule_class):
                is_valid_rule_class = True
                break
        if not is_valid_rule_class:
            return False
        optimizer_logger.debug("Adding rule {0}".format(rule))
        if len(rule.maturities) == 0:
            rule.maturities = self.maturities
        self.rules.add(rule)
        self.rules_usage_info[rule.name] = 0
        return True

    def reset_rule_usage_statistic(self):
        self.rules_usage_info = {}
        for rule in self.rules:
            self.rules_usage_info[rule.name] = 0

    def show_rule_usage_statistic(self):
        for rule_name, rule_nb_match in self.rules_usage_info.items():
            if rule_nb_match > 0:
                d810_logger.info("Instruction Rule '{0}' has been used {1} times".format(rule_name, rule_nb_match))

    def get_optimized_instruction(self, blk: mblock_t, ins: minsn_t):
        if blk is not None:
            self.cur_maturity = blk.mba.maturity
        # if self.cur_maturity not in self.maturities:
        #     return None
        for rule in self.rules:
            if self.cur_maturity not in rule.maturities:
                continue
            try:
                new_ins = rule.check_and_replace(blk, ins)
                if new_ins is not None:
                    self.rules_usage_info[rule.name] += 1
                    optimizer_logger.info("Rule {0} matched:".format(rule.name))
                    optimizer_logger.info("  orig: {0}".format(format_minsn_t(ins)))
                    optimizer_logger.info("  new : {0}".format(format_minsn_t(new_ins)))
                    return new_ins
            except RuntimeError as e:
                optimizer_logger.error("Runtime error during rule {0} for instruction {1}: {2}".format(rule, format_minsn_t(ins), e))
            except D810Exception as e:
                optimizer_logger.error("D810Exception during rule {0} for instruction {1}: {2}".format(rule, format_minsn_t(ins), e))
        return None

    @property
    def name(self):
        if self.NAME is not None:
            return self.NAME
        return self.__class__.__name__

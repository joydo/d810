import logging
from ida_hexrays import *
from d810.hexrays_formatters import format_minsn_t
from d810.optimizers.instructions.handler import InstructionOptimizer, InstructionOptimizationRule


optimizer_logger = logging.getLogger('D810.optimizer')


class InstructionAnalysisRule(InstructionOptimizationRule):
    def analyze_instruction(self, blk, ins):
        raise NotImplementedError


class InstructionAnalyzer(InstructionOptimizer):
    RULE_CLASSES = [InstructionAnalysisRule]

    def set_maturity(self, maturity: int):
        self.cur_maturity = maturity
        for rule in self.rules:
            rule.set_maturity(self.cur_maturity)

    def analyze(self, blk: mblock_t, ins: minsn_t):
        if blk is not None:
            self.cur_maturity = blk.mba.maturity

        if self.cur_maturity not in self.maturities:
            return None

        for rule in self.rules:
            try:
                rule.analyze_instruction(blk, ins)
            except RuntimeError:
                optimizer_logger.error("error during rule {0} for instruction {1}".format(rule, format_minsn_t(ins)))
        return None


    @property
    def name(self):
        if self.NAME is not None:
            return self.NAME
        return self.__class__.__name__

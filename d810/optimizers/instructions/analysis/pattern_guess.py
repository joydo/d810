import os

from d810.ast import minsn_to_ast
from d810.hexrays_formatters import format_minsn_t, format_mop_t, maturity_to_string

from d810.optimizers.handler import DEFAULT_INSTRUCTION_MATURITIES
from d810.optimizers.instructions.analysis.handler import InstructionAnalysisRule
from d810.optimizers.instructions.analysis.utils import get_possible_patterns


class ExampleGuessingRule(InstructionAnalysisRule):
    DESCRIPTION = "Detect pattern with variable used multiple times and with multiple different opcodes"

    def __init__(self):
        super().__init__()
        self.maturities = DEFAULT_INSTRUCTION_MATURITIES
        self.cur_maturity = None
        self.min_nb_var = 1
        self.max_nb_var = 3
        self.min_nb_diff_opcodes = 3
        self.max_nb_diff_opcodes = -1

        self.cur_index = 0
        self.max_index = 1000
        self.cur_ins_guessed = [""] * self.max_index
        self.pattern_filename_path = None

    def log_info(self, message):
        with open(self.pattern_filename_path, "a") as f:
            f.write('{0}\n'.format(message))

    def set_maturity(self, maturity):
        self.log_info("Patterns guessed at maturity {0}".format(maturity_to_string(maturity)))
        self.cur_maturity = maturity

    def set_log_dir(self, log_dir):
        super().set_log_dir(log_dir)
        self.pattern_filename_path = os.path.join(self.log_dir, "pattern_guess.log")
        f = open(self.pattern_filename_path, "w")
        f.close()

    def configure(self, kwargs):
        super().configure(kwargs)
        if "min_nb_var" in kwargs.keys():
            self.min_nb_var = kwargs["min_nb_var"]
        if "max_nb_var" in kwargs.keys():
            self.max_nb_var = kwargs["max_nb_var"]
        if "min_nb_diff_opcodes" in kwargs.keys():
            self.min_nb_diff_opcodes = kwargs["min_nb_diff_opcodes"]
        if "max_nb_diff_opcodes" in kwargs.keys():
            self.max_nb_diff_opcodes = kwargs["max_nb_diff_opcodes"]

        if self.max_nb_var == -1:
            self.max_nb_var = 0xff
        if self.max_nb_diff_opcodes == -1:
            self.max_nb_diff_opcodes = 0xff

    def analyze_instruction(self, blk, ins):
        if self.cur_maturity not in self.maturities:
            return None
        formatted_ins = str(format_minsn_t(ins))
        if formatted_ins in self.cur_ins_guessed:
            return False
        tmp = minsn_to_ast(ins)
        if tmp is None:
            return False
        is_good_candidate = self.check_if_possible_pattern(tmp)
        if is_good_candidate:
            self.cur_ins_guessed[self.cur_index] = formatted_ins
            self.cur_index = (self.cur_index + 1) % self.max_index
        return is_good_candidate

    def check_if_possible_pattern(self, test_ast):
        patterns = get_possible_patterns(test_ast, min_nb_use=2, ref_ast_info_by_index=None, max_nb_pattern=64)
        for pattern in patterns:
            leaf_info_list, cst_leaf_values, opcodes = pattern.get_information()
            leaf_nb_use = [leaf_info.number_of_use for leaf_info in leaf_info_list]
            if not(self.min_nb_var <= len(leaf_info_list) <= self.max_nb_var):
                continue
            if not(self.min_nb_diff_opcodes <= len(set(opcodes)) <= self.max_nb_diff_opcodes):
                continue
            if not(min(leaf_nb_use) >= 2):
                continue
            ins = pattern.mop.d
            self.log_info("IR: 0x{0:x} - {1}".format(ins.ea, format_minsn_t(ins)))
            for leaf_info in leaf_info_list:
                self.log_info("  {0} -> {1}".format(leaf_info.ast, format_mop_t(leaf_info.ast.mop)))
            self.log_info("Pattern: {0}".format(pattern))
            self.log_info("AstNode: {0}\n".format(pattern.get_pattern()))
            return True
        return False

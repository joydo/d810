from d810.optimizers.instructions.chain import CHAIN_RULES, ChainOptimizer
from d810.optimizers.instructions.pattern_matching import PATTERN_MATCHING_RULES, PatternOptimizer
from d810.optimizers.instructions.z3 import Z3_RULES, Z3Optimizer
from d810.optimizers.instructions.analysis import INSTRUCTION_ANALYSIS_RULES, InstructionAnalyzer
from d810.optimizers.instructions.early import EARLY_RULES, EarlyOptimizer

KNOWN_INS_RULES = PATTERN_MATCHING_RULES + CHAIN_RULES + Z3_RULES + EARLY_RULES + INSTRUCTION_ANALYSIS_RULES

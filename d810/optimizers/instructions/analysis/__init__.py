from d810.utils import get_all_subclasses
from d810.optimizers.instructions.analysis.handler import InstructionAnalyzer, InstructionAnalysisRule
from d810.optimizers.instructions.analysis.pattern_guess import *

INSTRUCTION_ANALYSIS_RULES = CHAIN_RULES = [x() for x in get_all_subclasses(InstructionAnalysisRule)]

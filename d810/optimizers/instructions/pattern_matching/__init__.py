from d810.utils import get_all_subclasses
from d810.optimizers.instructions.pattern_matching.handler import PatternMatchingRule, PatternOptimizer
from d810.optimizers.instructions.pattern_matching.rewrite_add import *
from d810.optimizers.instructions.pattern_matching.rewrite_and import *
from d810.optimizers.instructions.pattern_matching.rewrite_bnot import *
from d810.optimizers.instructions.pattern_matching.rewrite_cst import *
from d810.optimizers.instructions.pattern_matching.rewrite_mov import *
from d810.optimizers.instructions.pattern_matching.rewrite_mul import *
from d810.optimizers.instructions.pattern_matching.rewrite_neg import *
from d810.optimizers.instructions.pattern_matching.rewrite_predicates import *
from d810.optimizers.instructions.pattern_matching.rewrite_or import *
from d810.optimizers.instructions.pattern_matching.rewrite_sub import *
from d810.optimizers.instructions.pattern_matching.rewrite_xor import *
from d810.optimizers.instructions.pattern_matching.weird import *
from d810.optimizers.instructions.pattern_matching.experimental import *

PATTERN_MATCHING_RULES = [x() for x in get_all_subclasses(PatternMatchingRule)]



from d810.utils import get_all_subclasses
from d810.optimizers.instructions.early.handler import EarlyRule, EarlyOptimizer
from d810.optimizers.instructions.early.mem_read import *

EARLY_RULES = [x() for x in get_all_subclasses(EarlyRule)]

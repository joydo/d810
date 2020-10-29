from d810.utils import get_all_subclasses
from d810.optimizers.flow.jumps.handler import JumpOptimizationRule, JumpFixer
from d810.optimizers.flow.jumps.opaque import *
from d810.optimizers.flow.jumps.tricks import *


JUMP_OPTIMIZATION_RULES = [x() for x in get_all_subclasses(JumpOptimizationRule)]
jump_fixer = JumpFixer()
for jump_optimization_rule in JUMP_OPTIMIZATION_RULES:
    jump_fixer.register_rule(jump_optimization_rule)
JUMP_OPTIMIZATION_BLOCK_RULES = [jump_fixer]

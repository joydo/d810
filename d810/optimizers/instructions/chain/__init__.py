from d810.utils import get_all_subclasses
from d810.optimizers.instructions.chain.handler import ChainSimplificationRule, ChainOptimizer
from d810.optimizers.instructions.chain.chain_rules import *

CHAIN_RULES = [x() for x in get_all_subclasses(ChainSimplificationRule)]

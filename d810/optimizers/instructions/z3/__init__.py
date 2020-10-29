from d810.utils import get_all_subclasses
from d810.optimizers.instructions.z3.handler import Z3Rule, Z3Optimizer
from d810.optimizers.instructions.z3.cst import *
from d810.optimizers.instructions.z3.predicates import *


Z3_RULES = [x() for x in get_all_subclasses(Z3Rule)]

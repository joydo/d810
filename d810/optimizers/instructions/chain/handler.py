from d810.optimizers.instructions.handler import InstructionOptimizationRule, InstructionOptimizer


class ChainSimplificationRule(InstructionOptimizationRule):
    pass


class ChainOptimizer(InstructionOptimizer):
    RULE_CLASSES = [ChainSimplificationRule]

from d810.optimizers.instructions.handler import GenericPatternRule, InstructionOptimizer


class EarlyRule(GenericPatternRule):
    pass


class EarlyOptimizer(InstructionOptimizer):
    RULE_CLASSES = [EarlyRule]

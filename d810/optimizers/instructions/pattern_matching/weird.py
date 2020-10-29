from ida_hexrays import *
from d810.optimizers.instructions.pattern_matching.handler import PatternMatchingRule
from d810.ast import AstLeaf, AstConstant, AstNode
from d810.hexrays_helpers import equal_bnot_mop


class WeirdRule1(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstLeaf("x_0"),
                      AstNode(m_or,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")))
    REPLACEMENT_PATTERN = AstNode(m_add,
                                  AstNode(m_or,
                                          AstLeaf("x_0"),
                                          AstNode(m_bnot, AstLeaf("x_1"))),
                                  AstConstant("val_1"))

    def check_candidate(self, candidate):
        candidate.add_constant_leaf("val_1", 1, candidate.size)
        return True


class WeirdRule2(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstLeaf("x_0")),
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstNode(m_bnot, AstLeaf("x_1"))))
    REPLACEMENT_PATTERN = AstNode(m_add,
                                  AstLeaf("x_0"),
                                  AstNode(m_and,
                                          AstLeaf("x_0"),
                                          AstLeaf("x_1")))


class WeirdRule3(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstNode(m_bnot, AstLeaf("x_1"))),
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstLeaf("x_0")))
    REPLACEMENT_PATTERN = AstNode(m_neg,
                                  AstNode(m_add,
                                          AstLeaf("x_0"),
                                          AstNode(m_and,
                                                  AstLeaf("x_0"),
                                                  AstLeaf("x_1"))))


class WeirdRule4(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstLeaf("bnot_x_1")),
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")))
    REPLACEMENT_PATTERN = AstNode(m_sub,
                                  AstNode(m_xor,
                                          AstLeaf("x_0"),
                                          AstLeaf("x_1")),
                                  AstLeaf("x_1"))

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True


class WeirdRule5(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_add,
                              AstNode(m_or,
                                      AstLeaf("bnot_x_0"),
                                      AstNode(m_and,
                                              AstLeaf("bnot_x_1"),
                                              AstLeaf("x_2"))),
                              AstNode(m_add,
                                      AstLeaf("x_0"),
                                      AstNode(m_and,
                                              AstLeaf("x_1"),
                                              AstLeaf("x_2")))),
                      AstLeaf("x_2"))
    REPLACEMENT_PATTERN = AstNode(m_or,
                                  AstLeaf("x_0"),
                                  AstNode(m_or,
                                          AstLeaf("x_1"),
                                          AstNode(m_bnot,
                                                  AstLeaf("x_2"))))

    def check_candidate(self, candidate):
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        return True


class WeirdRule6(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstNode(m_or,
                              AstLeaf('x_0'),
                              AstLeaf('x_1')),
                      AstNode(m_and,
                              AstLeaf('x_0'),
                              AstNode(m_bnot,
                                      AstLeaf('x_1'))))
    REPLACEMENT_PATTERN = AstNode(m_add,
                                  AstNode(m_xor,
                                          AstLeaf("x_0"),
                                          AstLeaf("x_1")),
                                  AstLeaf('x_0'))

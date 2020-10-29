from ida_hexrays import *

from d810.optimizers.instructions.pattern_matching.handler import PatternMatchingRule
from d810.hexrays_helpers import AND_TABLE
from d810.ast import AstLeaf, AstConstant, AstNode


class Neg_HackersDelightRule_1(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstNode(m_bnot,
                              AstLeaf("x_0")),
                      AstConstant("1", 1))
    REPLACEMENT_PATTERN = AstNode(m_neg, AstLeaf("x_0"))


class Neg_HackersDelightRule_2(PatternMatchingRule):
    PATTERN = AstNode(m_bnot,
                      AstNode(m_sub,
                              AstLeaf("x_0"),
                              AstConstant("1", 1)))
    REPLACEMENT_PATTERN = AstNode(m_neg, AstLeaf("x_0"))


class NegAdd_HackersDelightRule_1(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_xor,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")),
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstNode(m_or,
                                      AstLeaf("x_0"),
                                      AstLeaf("x_1"))))
    REPLACEMENT_PATTERN = AstNode(m_neg,
                                  AstNode(m_add,
                                          AstLeaf("x_0"),
                                          AstLeaf("x_1")))


class NegAdd_HackersDelightRule_2(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_xor,
                              AstLeaf("x_0"),
                              AstNode(m_or,
                                      AstLeaf("x_1"),
                                      AstLeaf("x_2"))),
                      AstNode(m_mul,
                              AstConstant("2", 2),
                              AstNode(m_or,
                                      AstNode(m_or,
                                              AstLeaf("x_0"),
                                              AstLeaf("x_1")),
                                      AstLeaf("x_2"))))
    REPLACEMENT_PATTERN = AstNode(m_neg,
                                  AstNode(m_add,
                                          AstLeaf("x_0"),
                                          AstNode(m_or,
                                                  AstLeaf("x_1"),
                                                  AstLeaf("x_2"))))


class NegAdd_HackersDelightRule_1(PatternMatchingRule):
    PATTERN = AstNode(m_add,
                      AstNode(m_mul,
                              AstConstant('val_fe'),
                              AstNode(m_or,
                                      AstLeaf('x_0'),
                                      AstLeaf('x_1'))),
                      AstNode(m_xor,
                              AstLeaf('x_0'),
                              AstLeaf('x_1')))

    REPLACEMENT_PATTERN = AstNode(m_neg,
                                  AstNode(m_add,
                                          AstLeaf("x_0"),
                                          AstLeaf("x_1")))


    def check_candidate(self, candidate):
        if (candidate["val_fe"].value + 2) & AND_TABLE[candidate["val_fe"].size] != 0:
            return False
        return True

class NegOr_HackersDelightRule_1(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_and,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")),
                      AstNode(m_add,
                              AstLeaf("x_0"),
                              AstLeaf("x_1")))

    REPLACEMENT_PATTERN = AstNode(m_neg,
                                  AstNode(m_or,
                                          AstLeaf("x_0"),
                                          AstLeaf("x_1")))


class NegXor_HackersDelightRule_1(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_and,
                              AstLeaf('x_0'),
                              AstLeaf('x_1')),
                      AstNode(m_or,
                              AstLeaf('x_0'),
                              AstLeaf('x_1')))
    REPLACEMENT_PATTERN = AstNode(m_neg,
                                  AstNode(m_xor,
                                          AstLeaf("x_0"),
                                          AstLeaf("x_1")))


class NegXor_HackersDelightRule_2(PatternMatchingRule):
    PATTERN = AstNode(m_sub,
                      AstNode(m_add,
                              AstLeaf('x_0'),
                              AstLeaf('x_1')),
                      AstNode(m_mul,
                              AstConstant('2', 2),
                              AstNode(m_or,
                                      AstLeaf('x_0'),
                                      AstLeaf('x_1'))))
    REPLACEMENT_PATTERN = AstNode(m_neg,
                                  AstNode(m_xor,
                                          AstLeaf("x_0"),
                                          AstLeaf("x_1")))

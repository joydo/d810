from d810.optimizers.flow.flattening.unflattener import Unflattener
from d810.optimizers.flow.flattening.unflattener_switch_case import UnflattenerSwitchCase
from d810.optimizers.flow.flattening.unflattener_indirect import UnflattenerTigressIndirect
from d810.optimizers.flow.flattening.unflattener_fake_jump import UnflattenerFakeJump
from d810.optimizers.flow.flattening.fix_pred_cond_jump_block import FixPredecessorOfConditionalJumpBlock

UNFLATTENING_BLK_RULES = [Unflattener(), UnflattenerSwitchCase(), UnflattenerTigressIndirect(), UnflattenerFakeJump(),
                          FixPredecessorOfConditionalJumpBlock()]

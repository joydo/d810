class D810Exception(Exception):
    pass


class AstException(D810Exception):
    pass


class AstEvaluationException(AstException):
    pass


class D810Z3Exception(D810Exception):
    pass


class ControlFlowException(D810Exception):
    pass


class EmulationException(D810Exception):
    pass


class EmulationIndirectJumpException(EmulationException):
    def __init__(self, message, dest_ea, dest_serial_list):
        super().__init__(message)
        self.dest_ea = dest_ea
        self.dest_serial_list = dest_serial_list


class UnresolvedMopException(EmulationException):
    pass


class WritableMemoryReadException(EmulationException):
    pass


class UnsupportedInstructionException(EmulationException):
    pass

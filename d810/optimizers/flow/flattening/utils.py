import logging


tracker_logger = logging.getLogger('D810.tracker')
emulator_logger = logging.getLogger('D810.emulator')


class UnflatteningException(Exception):
    pass


class DispatcherUnflatteningException(UnflatteningException):
    pass


class NotDuplicableFatherException(UnflatteningException):
    pass


class NotResolvableFatherException(UnflatteningException):
    pass




def configure_mop_tracker_log_verbosity(verbose=False):
    tracker_log_level = tracker_logger.getEffectiveLevel()
    emulator_log_level = emulator_logger.getEffectiveLevel()
    if not verbose:
        tracker_logger.setLevel(logging.ERROR)
        emulator_logger.setLevel(logging.ERROR)
    return [tracker_log_level, emulator_log_level]


def restore_mop_tracker_log_verbosity(tracker_log_level, emulator_log_level):
    tracker_logger.setLevel(tracker_log_level)
    emulator_logger.setLevel(emulator_log_level)


def get_all_possibles_values(mop_histories, searched_mop_list, verbose=False):
    log_levels = configure_mop_tracker_log_verbosity(verbose)
    mop_cst_values_list = []
    for mop_history in mop_histories:
        mop_cst_values_list.append([mop_history.get_mop_constant_value(searched_mop)
                                    for searched_mop in searched_mop_list])
    restore_mop_tracker_log_verbosity(*log_levels)
    return mop_cst_values_list


def check_if_all_values_are_found(mop_cst_values_list):
    all_values_are_found = True
    for cst_list in mop_cst_values_list:
        if None in cst_list:
            all_values_are_found = False
            break
    return all_values_are_found

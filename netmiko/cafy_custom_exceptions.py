class PatternNotFoundException(Exception):
    """
    Raise by send_command when received pattern is not found in output
    """
    pass

class SessionDownException(Exception):
    """
    Raise when session goes down while finding prompt or
    waiting for prompt after sending command
    """
    pass

class PromptNotFoundException(Exception):
    """
    Raise by find_prompt when prompt is not found
    """
    pass

class ConfigModeExitError(Exception):
    """
    Raised by exit_config_mode when we cannot exit config mode
    """
    pass


class ConfigModeEnterError(Exception):
    """
    Raised by config_mode when we cannot enter config mode
    """
    pass


class ConfigCommitError(Exception):
    """
    Raised by commit when config commit fails
    """
    pass

LOOP_DELAY = 0.1

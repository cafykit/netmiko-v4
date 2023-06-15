from __future__ import print_function
from __future__ import unicode_literals


import re
import time
import logging
import warnings
import socket

from netmiko.cisco.cisco_xr import CiscoXrSSH
from netmiko.netmiko_globals import BACKSPACE_CHAR
from netmiko.utilities import get_structured_data
from netmiko.cafy_custom_exceptions import SessionDownException, PromptNotFoundException, PatternNotFoundException
from netmiko.cafy_custom_exceptions import ConfigCommitError, ConfigModeEnterError, ConfigModeExitError, LOOP_DELAY

log = logging.getLogger('netmiko')

DELAY_FACTOR_DEPR_SIMPLE_MSG = """\n
Delay Factor is not used in Cisco VXR SSH Netmiko Library.
Netmiko 4.x and later has deprecated the use of delay_factor.
You should remove any use of delay_factor=x from this method call.\n"""

MAX_LOOPS_DEPR_SIMPLE_MSG = """\n
Max Loops is not used in Cisco VXR SSH Netmiko Library.
Netmiko 4.x and later has deprecated the use of max_loops.
You should remove any use of max_loops=x from this method call.\n"""


class CiscoVxrSSH(CiscoXrSSH):
    """
    CiscoVxrSSH is based of CiscoXrSSH -- CiscoBaseConnection
    """

    def __init__(self, **kwargs):
        """Constructor
        """
        # 30 minutes
        self.read_timeout = kwargs.get('read_timeout', 1800)
        kwargs["blocking_timeout"] = self.read_timeout
        super().__init__(**kwargs)

    def session_preparation(self) -> None:
        """Prepare the session after the connection has been established."""
        # IOS-XR has an issue where it echoes the command even though it hasn't returned the prompt
        self._test_channel_read(pattern=r"[>#]")
        cmd = "terminal width 511"
        self.set_terminal_width(command=cmd, pattern=cmd)
        self.disable_paging()
        self.set_base_prompt()

    def write_channel(self, out_data):
        """Generic handler that will write to both SSH and telnet channel.

        :param out_data: data to be written to the channel
        :type out_data: str (can be either unicode/byte string)
        """
        # Netmiko4 already has @lock_channel decorator on write_channel() in base_Connection.py
        # Therefore below self._lock_netmiko_session() is commented
        #self._lock_netmiko_session()
        try:
            # Netmiko4 base_connection doesnt have _write_channel()
            # Therefore calling super().write_channel()  which has same functionality as netmiko2's _write_channel
            # self._write_channel(out_data)
            super().write_channel(out_data)
        except socket.error:
            msg = "Session went down while writing command on channel. Command: {}".format(out_data)
            self.log.error(msg)
            raise SessionDownException(msg)

    
    def read_until_pattern(self, pattern='', re_flags=0, max_loops=None, read_timeout=1800):
        """Function that reads channel until pattern is detected.

        pattern takes a regular expression.

        By default pattern will be self.base_prompt

        Note: this currently reads beyond pattern. In the case of SSH it reads MAX_BUFFER.
        In the case of telnet it reads all non-blocking data.

        There are dependencies here like determining whether in config_mode that are actually
        depending on reading beyond pattern.

        :param pattern: Regular expression pattern used to identify the command is done \
        (defaults to self.base_prompt)
        :type pattern: str (regular expression)

        :param re_flags: regex flags used in conjunction with pattern to search for prompt \
        (defaults to no flags)
        :type re_flags: int

        :param max_loops: max number of iterations to read the channel before raising exception.
            Will default to be based upon self.timeout.
        :type max_loops: int
        :param read_timeout: needs for netmiko4, session_preparation function in base_connection.py calls
        read_until_pattern with read_timeout arg. Inorder to handle that, this param is added here.
        """
        if max_loops is not None:
            warnings.warn(MAX_LOOPS_DEPR_SIMPLE_MSG, DeprecationWarning)
            log.warning(MAX_LOOPS_DEPR_SIMPLE_MSG)

        output = ''
        if not pattern:
            pattern = re.escape(self.base_prompt)
        self.log.debug("In read_until_pattern, read_timeout: {}, blocking_timeout: {}, pattern is: {}".format(
            self.read_timeout, self.blocking_timeout, pattern))

        start_time = time.time()
        current_time = time.time()

        # Keep reading data until pattern is found or session is alive or read_timeout is reached
        while current_time - start_time < self.read_timeout and self.remote_conn.closed == False:
            new_data = self.read_channel()
            output += new_data
            # TODO Netmiko4 base_connection doesnt have _write_session_log() defined. 
            # Therefore below line is commented to avoid Attribute error
            # self._write_session_log(new_data)

            if re.search(pattern, output, flags=re_flags):
                self.log.info("Pattern found. Time Waited: {}.".format(current_time - start_time))
                return output

            time.sleep(LOOP_DELAY)
            self.log.info("Pattern not found. Time waited: {}".format(current_time - start_time))
            current_time = time.time()
        else:
            if self.remote_conn.closed:
                msg = "Session went down while checking for pattern. Search pattern: {}".format(pattern)
                self.log.error(msg)
                raise SessionDownException(msg)
            else:
                msg = "Search Pattern not found after sending command and waiting for {} seconds. Expected Pattern: {}. Output: {}".format(
                    self.read_timeout, pattern, output)
                self.log.error(msg)
                raise PatternNotFoundException(msg)
    

    
    def find_prompt(self, delay_factor=None, pattern= None):
        """Finds the current network device prompt, last line only.

        :param delay_factor: See __init__: global_delay_factor
        :type delay_factor: int
        :param pattern: to keep compatibility with find_prompt() in base_connection
        """
        if delay_factor is not None:
            warnings.warn(DELAY_FACTOR_DEPR_SIMPLE_MSG, DeprecationWarning)
            log.warning(DELAY_FACTOR_DEPR_SIMPLE_MSG)

        self.clear_buffer()
        self.write_channel(self.RETURN)
        time.sleep(LOOP_DELAY)

        vxr_pattern = "last login"
        autocommand_pattern = "executing autocommand"
        cxr_pattern = "last switch-over"

        start_time = time.time()
        current_time = time.time()

        # Keep reading data until prompt is found or session is alive or read_timeout is reached
        while current_time - start_time < self.read_timeout and self.remote_conn.closed == False:
            prompt = self.read_channel().strip()

            if prompt:
                self.log.info("Prompt found. Time Waited: {}. Prompt found is: {}.".format(current_time - start_time, prompt))
                if vxr_pattern in prompt.lower() or autocommand_pattern in prompt.lower() or cxr_pattern in prompt.lower():
                    self.log.info("Pattern found in Prompt. Will retry.")
                    time.sleep(LOOP_DELAY + 3)
                    self.clear_buffer()
                    self.write_channel(self.RETURN)
                    time.sleep(LOOP_DELAY)
                else:
                    break
            else:
                self.log.info("Prompt not found. Time Waited: {}".format(current_time - start_time))
                time.sleep(LOOP_DELAY)

            current_time = time.time()
        else:
            if self.remote_conn.closed:
                msg = "Session went down while finding prompt"
                self.log.error(msg)
                raise SessionDownException(msg)
            else:
                msg = "Prompt not found after waiting for {} seconds".format(self.read_timeout)
                self.log.error(msg)
                raise PromptNotFoundException(msg)

        if self.ansi_escape_codes:
            prompt = self.strip_ansi_escape_codes(prompt)

        prompt = self.normalize_linefeeds(prompt)
        prompt = prompt.split(self.RESPONSE_RETURN)[-1]
        prompt = prompt.strip()

        time.sleep(LOOP_DELAY)
        self.clear_buffer()
        self.log.info("Prompt is: {}.".format(prompt))
        return prompt
    

    def send_command(self, command_string, expect_string=None, delay_factor=None, max_loops=None, auto_find_prompt=True,
                     strip_prompt=True, strip_command=True, normalize=True, use_textfsm=False, read_timeout=1800, cmd_verify=True):
        """
        Execute command_string on the SSH channel using a pattern-based mechanism. Generally
        used for show commands. By default this method will keep waiting to receive data until the
        network device prompt is detected. The current network device prompt will be determined
        automatically.

        :param command_string: The command to be executed on the remote device.
        :type command_string: str

        :param expect_string: Regular expression pattern to use for determining end of output.
            If left blank will default to being based on router prompt.
        :type expect_string: str

        :param delay_factor: Multiplying factor used to adjust delays (default: 1).
        :type delay_factor: int

        :param max_loops: max_loops is not used
        :type max_loops: int

        :param strip_prompt: Remove the trailing router prompt from the output (default: True).
        :type strip_prompt: bool

        :param strip_command: Remove the echo of the command from the output (default: True).
        :type strip_command: bool

        :param normalize: Ensure the proper enter is sent at end of command (default: True).
        :type normalize: bool

        :param use_textfsm: Process command output through TextFSM template (default: False).
        :type normalize: bool

        :param read_timeout: send_command() of execute() in cafykit passes read_timeout param that is needed for non vxr devices
        Therefore inorder to keep the api consistent, this param is added here

        :param cmd_verify: Verify command echo before proceeding (default: True)
        dialog() and transmirt_receive() in cafykit connection lib pass this cmd_verify=False argument, so need to handle in vxr_ssh code
        """
        if delay_factor is not None:
            warnings.warn(DELAY_FACTOR_DEPR_SIMPLE_MSG, DeprecationWarning)
            log.warning(DELAY_FACTOR_DEPR_SIMPLE_MSG)

        if max_loops is not None:
            warnings.warn(MAX_LOOPS_DEPR_SIMPLE_MSG, DeprecationWarning)
            log.warning(MAX_LOOPS_DEPR_SIMPLE_MSG)

        config_large_msg = "This could be a few minutes if your config is large"
        self.log.info("In send_command, read_timeout: {}, blocking_timeout: {}, command: {}".format(
            self.read_timeout, self.blocking_timeout, command_string))

        # Find the current router prompt
        if expect_string is None:
            if auto_find_prompt:
                prompt = self.find_prompt()
            else:
                prompt = self.base_prompt
            search_pattern = re.escape(prompt.strip())
        else:
            search_pattern = expect_string
        self.log.info("In send_command, search pattern: {}.".format(search_pattern))

        if normalize:
            command_string = self.normalize_cmd(command_string)

        self.clear_buffer()
        self.write_channel(command_string)

        output = ''
        start_time = time.time()
        current_time = time.time()

        # Keep reading data until search_pattern is found or session is alive or read_timeout is reached
        while current_time - start_time < self.read_timeout and self.remote_conn.closed == False:
            new_data = self.read_channel()
            if new_data:
                if self.ansi_escape_codes:
                    new_data = self.strip_ansi_escape_codes(new_data)

                output += new_data
                try:
                    lines = output.split(self.RETURN)
                    first_line = lines[0]
                    # First line is the echo line containing the command. In certain situations
                    # it gets repainted and needs filtered
                    if BACKSPACE_CHAR in first_line:
                        pattern = search_pattern + r'.*$'
                        first_line = re.sub(pattern, repl='', string=first_line)
                        lines[0] = first_line
                        output = self.RETURN.join(lines)
                except IndexError:
                    pass
                if re.search(search_pattern, output):
                    break

                if re.search(config_large_msg, output):
                    output = self.send_command(command_string=self.RETURN,
                                               auto_find_prompt=False, strip_prompt=False, strip_command=False, )
                    output += self.read_channel()
                    if re.search(search_pattern, output):
                        break
            else:
                time.sleep(LOOP_DELAY)
            self.log.info("Pattern not found. Time waited: {}".format(current_time - start_time))
            current_time = time.time()

        else:  # nobreak
            if self.remote_conn.closed:
                msg = "Session went down while checking for prompt after sending command. Search pattern: {}".format(
                    search_pattern)
                self.log.error(msg)
                raise SessionDownException(msg)
            else:
                if expect_string is None:
                    msg = "Prompt not found after sending command and waiting for {} seconds. Expected Prompt: {}. Output: {}".format(
                        self.read_timeout, search_pattern, output)
                    self.log.error(msg)
                    raise PromptNotFoundException(msg)
                else:
                    msg = "Search Pattern not found after sending command and waiting for {} seconds. Expected Pattern: {}. Output: {}".format(
                        self.read_timeout, search_pattern, output)
                    self.log.error(msg)
                    raise PatternNotFoundException(msg)
        output = self._sanitize_output(output, strip_command=strip_command,
                                       command_string=command_string, strip_prompt=strip_prompt)
        if use_textfsm:
            output = get_structured_data(output, platform=self.device_type,
                                         command=command_string.strip())
        return output

    def check_config_mode(self, check_string=')#', pattern=r"[#\$]"):
        """Checks if the device is in configuration mode or not.
        """
        self.write_channel('\n')
        try:
            output = self.read_until_pattern(pattern=pattern)
        except SessionDownException:
            msg = "Session went down while checking if router is in config mode"
            self.log.error(msg)
            raise SessionDownException(msg)
        except PatternNotFoundException:
            msg = "Prompt Mode Pattern not found. Pattern: {}".format(pattern)
            self.log.error(msg)
            raise PatternNotFoundException(msg)
        return check_string in output

    def config_mode(self, config_command='config term', pattern=''):
        """Enter into config_mode.

        :param config_command: Configuration command to send to the device
        :type config_command: str

        :param pattern: Pattern to terminate reading of channel
        :type pattern: str
        """
        if not pattern:
            pattern = self.base_prompt[:16]
        pattern = pattern + ".*config"
        output = ''
        if not self.check_config_mode():
            self.write_channel(self.normalize_cmd(config_command))
            try:
                output = self.read_until_pattern(pattern=pattern)
            except SessionDownException:
                msg = "Session went down while checking for config prompt after sending config command: {}".format(
                    config_command)
                self.log.error(msg)
                raise SessionDownException(msg)
            except PatternNotFoundException:
                msg = "Config Mode Pattern not found after sending config command. Config Command: {}, Pattern: {}".format(
                    config_command, pattern)
                self.log.error(msg)
                raise PatternNotFoundException(msg)
            if not self.check_config_mode():
                raise ConfigModeEnterError("Failed to enter configuration mode.")
        return output

    def send_config_set(self, config_commands=None, exit_config_mode=False, delay_factor=None,
                        max_loops=None, strip_prompt=False, strip_command=False,
                        config_mode_command=None, read_timeout=None):
        """
        Send configuration commands down the SSH channel.

        config_commands is an iterable containing all of the configuration commands.
        The commands will be executed one after the other.

        Automatically exits/enters configuration mode.

        :param config_commands: Multiple configuration commands to be sent to the device
        :type config_commands: list or string

        :param exit_config_mode: Determines whether or not to exit config mode after complete
        :type exit_config_mode: bool

        :param delay_factor: Factor to adjust delays
        :type delay_factor: int

        :param max_loops: Controls wait time in conjunction with delay_factor (default: 150)
        :type max_loops: int

        :param strip_prompt: Determines whether or not to strip the prompt
        :type strip_prompt: bool

        :param strip_command: Determines whether or not to strip the command
        :type strip_command: bool

        :param config_mode_command: The command to enter into config mode
        :type config_mode_command: str

        :param read_timeout: Absolute timer to send to read_channel_timing. Should be rarely needed
        Added this to make it consistent with same function in base_connection.py
        """
        if delay_factor is not None:
            warnings.warn(DELAY_FACTOR_DEPR_SIMPLE_MSG, DeprecationWarning)
            log.warning(DELAY_FACTOR_DEPR_SIMPLE_MSG)

        if max_loops is not None:
            warnings.warn(MAX_LOOPS_DEPR_SIMPLE_MSG, DeprecationWarning)
            log.warning(MAX_LOOPS_DEPR_SIMPLE_MSG)

        if config_commands is None:
            return ''
        elif isinstance(config_commands, (str, )):
            config_commands = (config_commands,)

        if not hasattr(config_commands, '__iter__'):
            raise ValueError("Invalid argument passed into send_config_set")

        cfg_mode_args = (config_mode_command,) if config_mode_command else tuple()
        output = self.config_mode(*cfg_mode_args)
        for cmd in config_commands:
            commands = cmd.split("\n")
            for command in commands:
                self.write_channel(self.normalize_cmd(command))
                try:
                    output += self.read_until_pattern(pattern=r'\)#$')
                except SessionDownException:
                    msg = "Session went down while checking for config prompt after sending command: {}".format(command)
                    self.log.error(msg)
                    raise SessionDownException(msg)
                except PatternNotFoundException:
                    msg = "Config Prompt not found after sending command: {}".format(command)
                    self.log.error(msg)
                    raise PatternNotFoundException(msg)
        if exit_config_mode:
            output += self.exit_config_mode()
        output = self._sanitize_output(output)
        self.log.debug("send_config_set Output: {}.".format(output))
        return output

    def commit(self, confirm=False, confirm_delay=None, comment='', label='', replace=False, best_effort=False, force=False,
               delay_factor=None, **kwargs):
        """
        Commit the candidate configuration.

        default (no options):
            command_string = commit
        confirm and confirm_delay:
            command_string = commit confirmed <confirm_delay>
        label (which is a label name):
            command_string = commit label <label>
        comment:
            command_string = commit comment <comment>

        supported combinations
        label and confirm:
            command_string = commit label <label> confirmed <confirm_delay>
        label and comment:
            command_string = commit label <label> comment <comment>

        All other combinations will result in an exception.

        failed commit message:
        % Failed to commit one or more configuration items during a pseudo-atomic operation. All
        changes made have been reverted. Please issue 'show configuration failed [inheritance]'
        from this session to view the errors

        message XR shows if other commits occurred:
        One or more commits have occurred from other configuration sessions since this session
        started or since the last commit was made from this session. You can use the 'show
        configuration commit changes' command to browse the changes.

        Exit of configuration mode with pending changes will cause the changes to be discarded and
        an exception to be generated.
        """
        if delay_factor is not None:
            warnings.warn(DELAY_FACTOR_DEPR_SIMPLE_MSG, DeprecationWarning)
            log.warning(DELAY_FACTOR_DEPR_SIMPLE_MSG)
        commit_error_dialog_dict = kwargs.get('commit_error_dialog_dict')
        if confirm and not confirm_delay:
            raise ValueError("Invalid arguments supplied to XR commit")
        if confirm_delay and not confirm:
            raise ValueError("Invalid arguments supplied to XR commit")
        if comment and confirm:
            raise ValueError("Invalid arguments supplied to XR commit")

        # wrap the comment in quotes
        if comment:
            if '"' in comment:
                raise ValueError("Invalid comment contains double quote")
            comment = '"{0}"'.format(comment)

        label = str(label)
        error_marker = 'Failed to'
        alt_error_marker = 'One or more commits have occurred from other'

        # Select proper command string based on arguments provided
        if label:
            if comment:
                command_string = 'commit label {0} comment {1}'.format(label, comment)
            elif confirm:
                command_string = 'commit label {0} confirmed {1}'.format(label, str(confirm_delay))
            else:
                command_string = 'commit label {0}'.format(label)
        elif confirm:
            command_string = 'commit confirmed {0}'.format(str(confirm_delay))
        elif comment:
            command_string = 'commit comment {0}'.format(comment)
        else:
            command_string = 'commit'
        if force:
            command_string = command_string.replace("commit", "commit force")
        if best_effort:
            command_string = command_string.replace("commit", "commit best-effort")
        if replace:
            command_string = command_string.replace("commit", "commit replace")
        self.log.info("commit string is: {}".format(command_string))

        output = ''
        if replace:
            commit_replace_marker = "This commit will replace or remove the entire running configuration"
            self.write_channel(self.normalize_cmd(command_string))
            try:
                output += self.read_until_pattern(pattern=commit_replace_marker)
            except SessionDownException:
                msg = "Session went down after sending commit replace command"
                self.log.error(msg)
                raise SessionDownException(msg)
            except PatternNotFoundException:
                msg = "Prompt not found after sending commit replace command"
                self.log.error(msg)
                raise PatternNotFoundException(msg)
            expect_string = r'\)#$' + "|" + alt_error_marker
            try:
                output += self.send_command_expect("yes", strip_prompt=False, strip_command=False,
                                                   expect_string=expect_string)
            except SessionDownException:
                msg = "Session went down while sending commit replace confirmation command"
                self.log.error(msg)
                raise SessionDownException(msg)
            except PatternNotFoundException:
                msg = "Prompt not found after sending commit replace confirmation command"
                self.log.error(msg)
                raise PatternNotFoundException(msg)
        else:
            expect_string = r'\)#$' + "|" + alt_error_marker
            try:
                output += self.send_command_expect(command_string, strip_prompt=False, strip_command=False,
                                                   expect_string=expect_string)
            except SessionDownException:
                msg = "Session went down while sending commit command"
                self.log.error(msg)
                raise SessionDownException(msg)
            except PatternNotFoundException:
                msg = "Prompt not found after sending commit command"
                self.log.error(msg)
                raise PatternNotFoundException(msg)

        if alt_error_marker in output:
            if commit_error_dialog_dict is not None and alt_error_marker in commit_error_dialog_dict:
                marker_value = commit_error_dialog_dict[alt_error_marker]
                self.write_channel(self.normalize_cmd(marker_value))
                output += self.read_until_pattern(pattern=r'\)#$')
            else:
                self.write_channel(self.normalize_cmd("no"))
                output += self.read_until_pattern(pattern=r'\)#$')
                raise ConfigCommitError(
                    "Commit failed as one or more commits have occurred from other configuration sessions:\n{0}".format(output))
        if error_marker in output:
            raise ConfigCommitError("Commit failed with the following errors:\n\n{0}".format(output))
        self.log.debug("commit Output: {0}".format(output))
        return output

    def exit_config_mode(self, exit_config='end', skip_check=False):
        """Exit configuration mode."""
        output = ''

        if skip_check or self.check_config_mode():
            self.write_channel(self.normalize_cmd(exit_config))
            try:
                output += self.read_until_pattern(pattern=r"(Uncommitted|#$)")
            except SessionDownException:
                msg = "Session went down while checking prompt after sending config mode exit command: {}".format(
                    exit_config)
                self.log.error(msg)
                raise SessionDownException(msg)
            except PatternNotFoundException:
                msg = "Exec Mode Pattern not found after sending config mode exit command: {}".format(exit_config)
                self.log.error(msg)
                raise PatternNotFoundException(msg)

            if "Uncommitted" in output:
                config_mode_exit_dialog_cmd = "no"
                self.write_channel(self.normalize_cmd(config_mode_exit_dialog_cmd))
                try:
                    output += self.read_until_pattern(pattern=r"#$")
                except SessionDownException:
                    msg = "Session went down while checking prompt after sending {} to exit confirmation dialog".format(
                        config_mode_exit_dialog_cmd)
                    self.log.error(msg)
                    raise SessionDownException(msg)
                except PatternNotFoundException:
                    msg = "Exec Mode Pattern not found after sending config mode exit dialog command: {}".format(config_mode_exit_dialog_cmd)
                    self.log.error(msg)
                    raise PatternNotFoundException(msg)

            if skip_check:
                return output
            if self.check_config_mode():
                raise ConfigModeExitError("Failed to exit configuration mode")
            self.log.debug("exit_config_mode Output: {0}".format(output))
        return output
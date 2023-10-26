from typing import Optional, Any, Union, Sequence, TextIO
import re
import warnings
from netmiko.base_connection import DELAY_FACTOR_DEPR_SIMPLE_MSG
from netmiko.cisco_base_connection import CiscoBaseConnection, CiscoFileTransfer
import logging
from netmiko.cafy_custom_exceptions import SessionDownException, PromptNotFoundException, PatternNotFoundException
from netmiko.cafy_custom_exceptions import ConfigCommitError, ConfigModeEnterError, ConfigModeExitError

log = logging.getLogger('netmiko')

class CiscoXrBase(CiscoBaseConnection):
    def establish_connection(self, width: int = 511, height: int = 511) -> None:
        """Establish SSH connection to the network device"""
        super().establish_connection(width=width, height=height)

    def session_preparation(self) -> None:
        """Prepare the session after the connection has been established."""
        # IOS-XR has an issue where it echoes the command even though it hasn't returned the prompt
        self._test_channel_read(pattern=r"[>#]")
        cmd = "terminal width 511"
        self.set_terminal_width(command=cmd, pattern=cmd)
        self.disable_paging()
        self._test_channel_read(pattern=r"[>#]")
        self.set_base_prompt()

    def send_config_set(
        self,
        config_commands: Union[str, Sequence[str], TextIO, None] = None,
        exit_config_mode: bool = False,
        **kwargs: Any,
    ) -> str:
        """IOS-XR requires you not exit from configuration mode."""
        return super().send_config_set(
            config_commands=config_commands, exit_config_mode=exit_config_mode, **kwargs
        )

    def commit(
        self,
        confirm: bool = False,
        confirm_delay: Optional[int] = None,
        comment: str = "",
        label: str = "",
        read_timeout: float = 120.0,
        delay_factor: Optional[float] = None,
        force=False,
        best_effort=False,
        replace=False,
        **kwargs
    ) -> str:
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

        delay_factor: Deprecated in Netmiko 4.x. Will be eliminated in Netmiko 5.

        force: Commit will be forcefully applied
        best_effort: Commit will be applied with the best effort
        replace:

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
        commit_error_dialog_dict = kwargs.get('commit_error_dialog_dict')
        if confirm and not confirm_delay:
            raise ValueError("Invalid arguments supplied to XR commit")
        if confirm_delay and not confirm:
            raise ValueError("Invalid arguments supplied to XR commit")
        if comment and confirm:
            raise ValueError("Invalid arguments supplied to XR commit")

        label = str(label)
        error_marker = "Failed to"
        alt_error_marker = "One or more commits have occurred from other"

        # Select proper command string based on arguments provided
        if label:
            if comment:
                command_string = f"commit label {label} comment {comment}"
            elif confirm:
                command_string = "commit label {} confirmed {}".format(
                    label, str(confirm_delay)
                )
            else:
                command_string = f"commit label {label}"
        elif confirm:
            command_string = f"commit confirmed {str(confirm_delay)}"
        elif comment:
            command_string = f"commit comment {comment}"
        else:
            command_string = "commit"

        if force:
            command_string = command_string.replace("commit", "commit force")
        if best_effort:
            command_string = command_string.replace("commit", "commit best-effort")
        if replace:
            command_string = command_string.replace("commit", "commit replace")

        # Enter config mode (if necessary)
        output = self.config_mode()

        if replace:
            try:
                new_data = self._send_command_str(
                    command_string,
                    expect_string=r"This commit will replace or remove the entire running configuration",
                    strip_prompt=False,
                    strip_command=False,
                    read_timeout=read_timeout,
                )
            except SessionDownException:
                msg = "Session went down after sending commit replace command"
                self.log.error(msg)
                raise SessionDownException(msg)
            except PatternNotFoundException:
                msg = "Prompt not found after sending commit replace command"
                self.log.error(msg)
                raise PatternNotFoundException(msg)
            
            try:
                if "This commit will replace or remove the entire running configuration" in new_data:
                    output += new_data
                    new_data = self._send_command_str(
                        "yes",
                        expect_string=r"#",
                        strip_prompt=False,
                        strip_command=False,
                        read_timeout=read_timeout,
                    )
            except SessionDownException:
                msg = "Session went down while sending commit replace confirmation command"
                self.log.error(msg)
                raise SessionDownException(msg)
            except PatternNotFoundException:
                msg = "Prompt not found after sending commit replace confirmation command"
                self.log.error(msg)
                raise PatternNotFoundException(msg)
            
        else:
            # IOS-XR might do this:
            # This could be a few minutes if your config is large. Confirm? [y/n][confirm]
            try:
                new_data = self._send_command_str(
                    command_string,
                    expect_string=r"(#|onfirm)",
                    strip_prompt=False,
                    strip_command=False,
                    read_timeout=read_timeout,
                )
            except SessionDownException:
                msg = "Session went down while sending commit command"
                self.log.error(msg)
                raise SessionDownException(msg)
            except PatternNotFoundException:
                msg = "Prompt not found after sending commit command"
                self.log.error(msg)
                raise PatternNotFoundException(msg)
            if "onfirm" in new_data:
                output += new_data
                try:
                    new_data = self._send_command_str(
                        "y",
                        expect_string=r"#",
                        strip_prompt=False,
                        strip_command=False,
                        read_timeout=read_timeout,
                    )
                except SessionDownException:
                    msg = "Session went down while sending commit confirmation command"
                    self.log.error(msg)
                    raise SessionDownException(msg)
                except PatternNotFoundException:
                    msg = "Prompt not found after sending commit confirmation command"
                    self.log.error(msg)
                    raise PatternNotFoundException(msg)
        output += new_data

        if alt_error_marker in output:
            if commit_error_dialog_dict is not None and alt_error_marker in commit_error_dialog_dict:
                marker_value = commit_error_dialog_dict[alt_error_marker]
                output += new_data
                new_data = self._send_command_str(
                    marker_value,
                    expect_string=r"\)#$",
                    strip_prompt=False,
                    strip_command=False,
                    read_timeout=read_timeout,
                )
                output += new_data
            else:
            # Other commits occurred, don't proceed with commit
                output += self._send_command_timing_str(
                    "no", strip_prompt=False, strip_command=False
                )
                raise ConfigCommitError(f"Commit failed as one or more commits have occurred from other configuration sessions:\n\n{output}")
        self.log.debug(f"Commit output: {output}")   
        if error_marker in output:
            raise ConfigCommitError(f"Commit failed with the following errors:\n\n{output}")
        return output

    def check_config_mode(
        self, check_string: str = ")#", pattern: str = r"[#\$]"
    ) -> bool:
        """Checks if the device is in configuration mode or not.

        IOS-XR, unfortunately, does this:
        RP/0/RSP0/CPU0:BNG(admin)#
        """
        try:
            self.write_channel(self.RETURN)
            output = self.read_until_pattern(pattern=pattern)
        except SessionDownException:
            msg = f"Session went down while checking if router is in config mode"
            self.log.error(msg)
            raise SessionDownException(msg)
        except PatternNotFoundException:
            msg = f"Prompt Mode Pattern not found. Pattern: {pattern}"
            self.log.error(msg)
            raise PatternNotFoundException(msg)
        # Strip out (admin) so we don't get a false positive with (admin)#
        # (admin-config)# would still match.
        output = output.replace("(admin)", "")
        return check_string in output

    def config_mode(
        self,
        config_command: str = "config terminal",
        pattern: str = "",
        re_flags: int = 0,
    ) -> str:
        if not pattern:
            # Make sure the *entire* config prompt is read.
            pattern = re.escape(self.base_prompt[:16])
            check_string = re.escape(")#")
            pattern = f"{pattern}.*{check_string}"
        return super().config_mode(
            config_command=config_command, pattern=pattern, re_flags=re_flags
        )

    def exit_config_mode(self, exit_config: str = "end", pattern: str = "", skip_check=False) -> str:
        """Exit configuration mode."""
        output = ""
        if skip_check or self.check_config_mode():
            self.write_channel(self.normalize_cmd(exit_config))
            # Make sure you read until you detect the command echo (avoid getting out of sync)
            if self.global_cmd_verify is not False:
                output += self.read_until_pattern(
                    pattern=re.escape(exit_config.strip())
                )
            # Read until we detect either an Uncommitted change or the end prompt
            # For asr9k, fretta devices, admin prompt has a space after '#' like
            # 'sysadmin-vm:0_RSP0#  '
            # See the space after '#' in the above prompt. To handle this the regex is looking for zero or more space at the end of prompt
            # therefore the regex is r"(Uncommitted|#\s*$)
            try:
                if not re.search(r"(Uncommitted|#\s*$)", output):
                    output += self.read_until_pattern(pattern=r"(Uncommitted|#\s*$)")
            except SessionDownException:
                msg = f"Session went down while checking prompt after sending config mode exit command: {exit_config}"
                self.log.error(msg)
                raise SessionDownException(msg)
            except PatternNotFoundException:
                msg = f"Exec Mode Pattern not found after sending config mode exit command: {exit_config}"
                self.log.error(msg)
                raise PatternNotFoundException(msg)
            if "Uncommitted" in output:
                self.write_channel(self.normalize_cmd("no\n"))
                try:
                    output += self.read_until_pattern(pattern=r"[>#]")
                except SessionDownException:
                    msg = f"Session went down while checking prompt after sending 'no' to exit confirmation dialog"
                    self.log.error(msg)
                    raise SessionDownException(msg)
                except PatternNotFoundException:
                    msg = f"Exec Mode Pattern not found after sending config mode exit dialog command: no"
                    self.log.error(msg)
                    raise PatternNotFoundException(msg)
            if not re.search(pattern, output, flags=re.M):
                output += self.read_until_pattern(pattern=pattern)
            if skip_check:
                return output
            if self.check_config_mode():
                raise ConfigModeExitError("Failed to exit configuration mode")
            self.log.debug("exit_config_mode Output: {0}".format(output))
        return output

    def save_config(self, *args: Any, **kwargs: Any) -> str:
        """Not Implemented (use commit() method)"""
        raise NotImplementedError


class CiscoXrSSH(CiscoXrBase):
    """Cisco XR SSH driver."""

    pass


class CiscoXrTelnet(CiscoXrBase):
    """Cisco XR Telnet driver."""
    pass
    
    def session_preparation(self):
        """Prepare the session after the connection has been established."""
        self.write_channel('\r\n')
        out = self.set_base_prompt()
        if 'RP Node is not ' in out:
            return
        cmd = "terminal width 511"
        # self.set_terminal_width(command=cmd, pattern=cmd)
        # self._test_channel_read(pattern=r"[>#$:]")
        # self.disable_paging()
        # self._test_channel_read(pattern=r"[>#$:]")
        

    def set_base_prompt(
        self,
        pri_prompt_terminator: str = "#",
        alt_prompt_terminator: str = ">",
        alt_prompt_terminator_2: str = ":",
        standby_prompt='RP Node is not ',
        delay_factor: float = 1.0,
        pattern: Optional[str] = None,
    ) -> str:
        """Sets self.base_prompt

        Used as delimiter for stripping of trailing prompt in output.

        Should be set to something that is general and applies in multiple contexts. For Cisco
        devices this will be set to router hostname (i.e. prompt without > or #).

        This will be set on entering user exec or privileged exec on Cisco, but not when
        entering/exiting config mode.

        :param pri_prompt_terminator: Primary trailing delimiter for identifying a device prompt

        :param alt_prompt_terminator: Alternate trailing delimiter for identifying a device prompt

        :param standby_prompt: standby_prompt 

        :param delay_factor: See __init__: global_delay_factor

        :param pattern: Regular expression pattern to search for in find_prompt() call
        """
        out = self.find_prompt(delay_factor=delay_factor)
        if standby_prompt in out:
            self.base_prompt = out
            return self.base_prompt
        
        if pattern is None:
            if pri_prompt_terminator and alt_prompt_terminator and alt_prompt_terminator_2:
                pri_term = re.escape(pri_prompt_terminator)
                alt_term = re.escape(alt_prompt_terminator)
                alt_term_2 = re.escape(alt_prompt_terminator_2)
                pattern = rf"({pri_term}|{alt_term}|{alt_term_2}|\$)"
            elif pri_prompt_terminator:
                pattern = re.escape(pri_prompt_terminator)
            elif alt_prompt_terminator:
                pattern = re.escape(alt_prompt_terminator)
            elif alt_prompt_terminator_2:
                pattern = re.escape(alt_prompt_terminator_2)

        if pattern:
            prompt = self.find_prompt(delay_factor=delay_factor, pattern=pattern)
        else:
            prompt = self.find_prompt(delay_factor=delay_factor)

        if not prompt[-1] in (pri_prompt_terminator, alt_prompt_terminator, standby_prompt, alt_prompt_terminator_2):
            raise PromptNotFoundException(f"Router prompt not found: {repr(prompt)}")
        # Strip off trailing terminator
        self.base_prompt = prompt[:-1]
        return self.base_prompt
    
class CiscoVxrTelnet(CiscoXrTelnet):
   pass

class CiscoXrFileTransfer(CiscoFileTransfer):
    """Cisco IOS-XR SCP File Transfer driver."""

    @staticmethod
    def process_md5(md5_output: str, pattern: str = r"^([a-fA-F0-9]+)$") -> str:
        """
        IOS-XR defaults with timestamps enabled

        # show md5 file /bootflash:/boot/grub/grub.cfg
        Sat Mar  3 17:49:03.596 UTC
        c84843f0030efd44b01343fdb8c2e801
        """
        match = re.search(pattern, md5_output, flags=re.M)
        if match:
            return match.group(1)
        else:
            raise ValueError(f"Invalid output from MD5 command: {md5_output}")

    def remote_md5(
        self, base_cmd: str = "show md5 file", remote_file: Optional[str] = None
    ) -> str:
        """
        IOS-XR for MD5 requires this extra leading /

        show md5 file /bootflash:/boot/grub/grub.cfg
        """
        if remote_file is None:
            if self.direction == "put":
                remote_file = self.dest_file
            elif self.direction == "get":
                remote_file = self.source_file
        # IOS-XR requires both the leading slash and the slash between file-system and file here
        remote_md5_cmd = f"{base_cmd} /{self.file_system}/{remote_file}"
        dest_md5 = self.ssh_ctl_chan._send_command_str(remote_md5_cmd, read_timeout=300)
        dest_md5 = self.process_md5(dest_md5)
        return dest_md5

    def enable_scp(self, cmd: str = "") -> None:
        raise NotImplementedError

    def disable_scp(self, cmd: str = "") -> None:
        raise NotImplementedError


class CiscoCxrHa(CiscoXrTelnet):
    def find_prompt(self, delay_factor=1, pattern=r'[a-z0-9]$', verbose=False, telnet_return='\n'):
        return super().find_prompt(delay_factor=delay_factor, pattern=pattern)

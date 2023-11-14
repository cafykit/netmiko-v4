from netmiko.cisco_base_connection import CiscoBaseConnection
from typing import Optional, Any, Union, Sequence, TextIO
import re
import time
from netmiko.exceptions import NetmikoAuthenticationException
from netmiko.cafy_custom_exceptions import PromptNotFoundException

class CiscoLTPTelnet(CiscoBaseConnection):
    """
    Cisco telnet driver for images that put you directly into a linux shell, no XR prompt. For example, LTP testing.
    Adds support for characters like $, :
    Also has a custom base prompt for LTP images.
    """

    def _prompt_handler(self, auto_find_prompt: bool) -> str:
        # lets say prompt = [Image from ramfs ios:~]$
        # now lets say I ran a cd command, and its now: [Image from ramfs ios:/opt/ltp]$
        # so the regexp should really be r"\[Image from ramfs ios:[^\]]+\]\$"
        return r"\[Image from ramfs ios:[^\]]+\]\$"
    
    def session_preparation(self):
        """Prepare the session after the connection has been established."""
        self.write_channel('\r\n')
        out = self.set_base_prompt()
        if 'RP Node is not ' in out:
            return
        cmd = "terminal width 511"
        self.set_terminal_width(command=cmd, pattern=cmd)

        
    def telnet_login(
        self,
        pri_prompt_terminator: str = r"\#\s*$",
        alt_prompt_terminator: str = r">\s*$",
        alt_prompt_terminator_2: str = r"$\s*$",
        username_pattern: str = r"(?:user:|username|login|user name)",
        pwd_pattern: str = r"assword|ecret",
        delay_factor: float = 1.0,
        max_loops: int = 20,
    ) -> str:
        """Telnet login. Can be username/password or just password."""
        delay_factor = self.select_delay_factor(delay_factor)

        if delay_factor < 1:
            if not self._legacy_mode and self.fast_cli:
                delay_factor = 1

        time.sleep(1 * delay_factor)

        output = ""
        return_msg = ""
        outer_loops = 3
        inner_loops = int(max_loops / outer_loops)
        i = 1
        is_spitfire = False
        for _ in range(outer_loops):
            while i <= inner_loops:
                try:
                    self.log.debug("Reading channel for the first time")
                    output = self.read_channel()

                    # This below if block is addeed because when the telnet console starts with UserName,
                    # self.read_channel which internally calls telnetlib.read_ver_eager() returns empty string
                    # So, assign it to self.find_prompt()
                    self.log.debug("Output after reading channel for first time: {}".format(output))
                    if output == '':
                        time.sleep(2 * delay_factor)
                        self.log.debug("output is empty, doing find_prompt()")
                        #output = self.find_prompt()
                        output = self.find_prompt_special_case()

                    self.log.debug("Output after doing find_prompt: {}".format(output))
                    return_msg += output

                    # is at spitfire xr prompt
                    if re.search('RP/\d+/RP\d+/CPU\d+:\S*#$', output):
                        return return_msg

                    # At Rebooted BMC prompt
                    # reboot_bmc_to_bmc_cmd = 'boot'
                    rebooted_bmc_prompt_pattern = r"cisco-bmc#"
                    if re.search(rebooted_bmc_prompt_pattern, output):
                        self.write_channel(self.TELNET_RETURN + "boot" + self.TELNET_RETURN)
                        time.sleep(60 * delay_factor)
                        self.write_channel(self.TELNET_RETURN)
                        output = self.read_channel()
                        return_msg += output

                    # At BMC prompt
                    bmc_prompt_pattern = r"root@spitfire-arm:~#"
                    if re.search(bmc_prompt_pattern, output):
                        self.write_channel(self.TELNET_RETURN + "\x17" + self.TELNET_RETURN)
                        time.sleep(1 * delay_factor)
                        output = self.read_channel()
                        return_msg += output

                    # Search for linux host prompt pattern [xr:~] or x86 prompt pattern
                    linux_prompt_pattern = r"(\[xr:~]\$)|(\[[\w\-]+:~\]\$$)"
                    switch_to_xr_command = 'xr'
                    x86_prompt_pattern = r"(\S+@xr:~#)|(\S+@ios:~#)"
                    if re.search(linux_prompt_pattern, output) or re.search(x86_prompt_pattern, output):
                        self.write_channel(self.TELNET_RETURN + "xr" + self.TELNET_RETURN)
                        time.sleep(1 * delay_factor)
                        output = self.read_channel()
                        return_msg += output

                    # If previously from xr prompt, if bash was executed to go to linux host prompt,
                    # then inorder to go back to xr prompt, no need of xrlogin and password,
                    # just do "exit" cmd
                    xr_no_login_pattern = "Exec cannot be started from within an existing exec session"
                    if re.search(xr_no_login_pattern, output):
                        self.write_channel(self.TELNET_RETURN + "exit" + self.TELNET_RETURN)
                        time.sleep(1 * delay_factor)
                        output = self.read_channel()
                        return_msg += output
                        if pri_prompt_terminator in output or alt_prompt_terminator in output or alt_prompt_terminator_2 in output:
                            return return_msg

                    # If previously from xr prompt, XR not started, must restart XR
                    xr_not_started = r"(error while loading shared libraries)|(cannot open shared object)"
                    if re.search(xr_not_started, output):
                        self.write_channel("initctl start ios-xr.routing.start" + self.TELNET_RETURN)
                        time.sleep(60 * delay_factor)
                        self.write_channel(self.TELNET_RETURN)
                        output = self.read_channel()
                        return_msg += output

                    # Search for standby console pattern
                    standby_pattern = r"RP Node is not ready or active for login"
                    if re.search(standby_pattern, output):
                        ''' Session is standby state '''
                        return return_msg

                    # Search for username pattern / send username
                    # If the prompt shows "xr login:", the you can directly login to xr using xr username
                    # and password or you can login to linux host, using linux host's username password
                    self.log.debug("Searching for username pattern")
                    my_password = self.password
                    if re.search(username_pattern, output, flags=re.I):
                        # Sometimes username/password must be terminated with "\r" and not "\r\n"
                        self.log.debug("Username pattern detected, sending Username={}".format(self.username))
                        time.sleep(1)
                        bmc_login_pattern = "spitfire-arm login:"
                        if re.search(bmc_login_pattern, output):
                            my_password = '0penBmc'
                        else:
                            my_password = self.password
                        self.write_channel(self.username + "\r")
                        time.sleep(1 * delay_factor)
                        output = self.read_channel()
                        return_msg += output
                        self.log.debug("After sending username, the output pattern is={}".format(output))
                        self.log.debug("________________________________________________")
                    else:
                        xr_or_host_login_pattern = "xr login:"
                        xr_or_host_login_alt_pattern = "ios login:"
                        if re.search(xr_or_host_login_pattern, output) or re.search(xr_or_host_login_alt_pattern,
                                                                                    output):
                            self.write_channel(self.username + self.TELNET_RETURN)
                            time.sleep(1 * delay_factor)
                            output = self.read_channel()
                            return_msg += output

                    # Search for password pattern / send password
                    if re.search(pwd_pattern, output, flags=re.I):
                        # Sometimes username/password must be terminated with "\r" and not "\r\n"
                        assert isinstance(my_password, str)
                        self.write_channel(my_password + "\r")
                        time.sleep(0.5 * delay_factor)
                        output = self.read_channel()
                        return_msg += output
                        if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(alt_prompt_terminator, output, flags=re.M) or re.search(alt_prompt_terminator_2, output, flags=re.M) and \
                                not re.search(x86_prompt_pattern, output):
                            return return_msg

                        if re.search(pwd_pattern, output):
                            self.write_channel(my_password + self.TELNET_RETURN)
                            time.sleep(.5 * delay_factor)
                            output = self.read_channel()
                            return_msg += output

                    # Search for "VR0 con0/RP0/CPU0 is now available Press RETURN to get started" pattern
                    # on Sunstone devices
                    sunstone_pattern = r'Press RETURN to get started\.$'
                    if re.search(sunstone_pattern, output):
                        print("*****Sunstone pattern detected")
                        self.write_channel(self.TELNET_RETURN)
                        output = self.read_channel()

                    # Support direct telnet through terminal server
                    if re.search(
                        r"initial configuration dialog\? \[yes/no\]: ", output
                    ):
                        self.write_channel("no" + self.TELNET_RETURN)
                        time.sleep(0.5 * delay_factor)
                        count = 0
                        while count < 15:
                            output = self.read_channel()
                            return_msg += output
                            if re.search(r"ress RETURN to get started", output):
                                output = ""
                                break
                            time.sleep(2 * delay_factor)
                            count += 1

                    # Check for device with no password configured
                    if re.search(r"assword required, but none set", output):
                        assert self.remote_conn is not None
                        self.remote_conn.close()
                        msg = (
                            "Login failed - Password required, but none set: {}".format(
                                self.host
                            )
                        )
                        raise NetmikoAuthenticationException(msg)

                    if re.search(rebooted_bmc_prompt_pattern, output) or \
                            re.search(bmc_prompt_pattern, output) or \
                            re.search(x86_prompt_pattern, output):
                        is_spitfire = True

                    # Check if proper data received
                    if re.search(
                        pri_prompt_terminator, output, flags=re.M) or re.search(alt_prompt_terminator, output, flags=re.M) or re.search(alt_prompt_terminator_2, output, flags=re.M) and not is_spitfire:
                        return return_msg

                    i += 1

                except EOFError:
                    assert self.remote_conn is not None
                    self.remote_conn.close()
                    msg = f"EOFError Telnet Login failed: {self.host}"
                    raise NetmikoAuthenticationException(msg)

            # Try sending an <enter> to restart the login process
            self.write_channel(self.TELNET_RETURN)
            time.sleep(0.5 * delay_factor)
            i = 1

        # Last try to see if we already logged in
        self.write_channel(self.TELNET_RETURN)
        time.sleep(0.5 * delay_factor)
        output = self.read_channel()
        return_msg += output
        if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(alt_prompt_terminator, output, flags=re.M) or re.search(alt_prompt_terminator_2, output, flags=re.M):
            return return_msg

        assert self.remote_conn is not None
        self.remote_conn.close()
        msg = f"Login failed: {self.host}"
        raise NetmikoAuthenticationException(msg)

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
                pattern = rf"({pri_term}|{alt_term}|{alt_term_2})"
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
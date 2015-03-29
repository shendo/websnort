# Websnort - Web service for analysing pcap files with snort
# Copyright (C) 2013-2015 Steve Henderson
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from datetime import datetime
import os
import re
import shlex
from subprocess import PIPE, Popen

ALERT_PATTERN = re.compile(
    r"(?P<timestamp>\d{2}/\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[\d+:(?P<sid>\d+):(?P<revision>\d+)\] "
    r"(?P<message>.+) \[\*\*\]\s+\[Classification: (?P<classtype>.+)\] "
    r"\[Priority: (?P<priority>\d+)\] \{(?P<protocol>\w+)\} "
    r"(?P<src>.+) \-\> (?P<dest>.+)")

VERSION_PATTERN = re.compile(
    r".*\s+Version (?P<version>[\d\.]+ .*)"
)

class Snort(object):

    def __init__(self, conf):
        self.conf = conf

    def _snort_cmd(self, pcap):
        """Given a pcap filename, get the commandline to run.
        @param pcap: Pcap filename to scan
        @return: list of snort command args to scan supplied pcap file
        """
        cmdline = "'{0}' -A console -N -y -c '{1}' {2} -r '{3}'" \
            .format(self.conf['path'], self.conf['config'],
                    self.conf['extra_args'] or '', pcap)
        # can't seem to capture stderr from snort on windows
        # unless launched via cmd shell
        if 'nt' in os.name:
            cmdline = "cmd.exe /c " + cmdline
        return shlex.split(cmdline)

    def run(self, pcap):
        """Runs snort against the supplied pcap.
        @return: Dict with details/results of run
        """
        proc = Popen(self._snort_cmd(pcap), stdout=PIPE,
                     stderr=PIPE, universal_newlines=True)
        stdout, stderr = proc.communicate()
        if proc.returncode != 0:
            raise Exception("\n".join(["Execution failed return code: {0}" \
                                .format(proc.returncode), stderr or ""]))

        return (parse_version(stderr),
                [ x for x in parse_alert(stdout) ])

def parse_version(output):
    """Parses the supplied output and returns the version string.
    @param output: A string containing the output of running snort.
    @return: Version string for the version of snort run. None if not found.
    """
    for x in output.splitlines():
        match = VERSION_PATTERN.match(x)
        if match:
            return match.group('version').strip()
    return None

def parse_alert(output):
    """Parses the supplied output and yields any alerts.
    
    Example alert format:
    01/28/14-22:26:04.885446  [**] [1:1917:11] INDICATOR-SCAN UPnP service discover attempt [**] [Classification: Detection of a Network Scan] [Priority: 3] {UDP} 10.1.1.132:58650 -> 239.255.255.250:1900

    @param output: A string containing the output of running snort
    @return: Generator of snort alert dicts
    """
    for x in output.splitlines():
        match = ALERT_PATTERN.match(x)
        if match:
            yield {'timestamp': datetime.strptime(match.group('timestamp'),
                                                  '%m/%d/%y-%H:%M:%S.%f'),
                   'sid': int(match.group('sid')),
                   'revision': int(match.group('revision')),
                   'classtype': match.group('classtype'),
                   'message': match.group('message'),
                   'source': match.group('src'),
                   'destination': match.group('dest'),
                   'protocol': match.group('protocol'),
                   }

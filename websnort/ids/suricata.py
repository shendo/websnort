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
import shutil
from subprocess import PIPE, Popen
import tempfile

ALERT_PATTERN = re.compile(
    r"(?P<timestamp>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[\d+:(?P<sid>\d+):(?P<revision>\d+)\] "
    r"(?P<message>.+) \[\*\*\]\s+\[Classification: (?P<classtype>.+)\] "
    r"\[Priority: (?P<priority>\d+)\] \{(?P<protocol>\w+)\} "
    r"(?P<src>.+) \-\> (?P<dest>.+)")

VERSION_PATTERN = re.compile(
    r".*\s+This is Suricata version (?P<version>[\d\.]+ .*)"
)

class Suricata(object):

    def __init__(self, conf):
        self.conf = conf

    def _suri_cmd(self, pcap, logs):
        """Given a pcap filename, get the commandline to run.
        @param pcap: Pcap filename to scan
        @param logs: Output directory for logs
        @return: list of command args to scan supplied pcap file
        """
        cmdline = "'{0}' -c '{1}' -l '{2}' {3} -r '{4}'" \
            .format(self.conf['path'], self.conf['config'],
                    logs, self.conf['extra_args'] or '', pcap)
        # can't seem to capture stderr on windows
        # unless launched via cmd shell
        if 'nt' in os.name:
            cmdline = "cmd.exe /c " + cmdline
        return shlex.split(cmdline)

    def run(self, pcap):
        """Runs suricata against the supplied pcap.
        @return: Dict with details/results of run
        """
        tmpdir = None
        try:
            tmpdir = tempfile.mkdtemp(prefix='tmpsuri')
            proc = Popen(self._suri_cmd(pcap, tmpdir), stdout=PIPE,
                     stderr=PIPE, universal_newlines=True)
            stdout, stderr = proc.communicate()
            if proc.returncode != 0:
                raise Exception("\n".join(["Execution failed return code: {0}" \
                                .format(proc.returncode), stderr or ""]))

            with open(os.path.join(tmpdir, 'fast.log')) as tmp:
                return (parse_version(stdout),
                    [ x for x in parse_alert(tmp.read()) ])
        finally:
            if tmpdir:
                shutil.rmtree(tmpdir)

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
    01/28/2014-22:26:04.885446  [**] [1:1917:11] INDICATOR-SCAN UPnP service discover attempt [**] [Classification: Detection of a Network Scan] [Priority: 3] {UDP} 10.1.1.132:58650 -> 239.255.255.250:1900

    @param output: A string containing the the fast.log contents
    @return: Generator of suricata alert dicts
    """
    for x in output.splitlines():
        match = ALERT_PATTERN.match(x)
        if match:
            yield {'timestamp': datetime.strptime(match.group('timestamp'),
                                                  '%m/%d/%Y-%H:%M:%S.%f'),
                   'sid': int(match.group('sid')),
                   'revision': int(match.group('revision')),
                   'classtype': match.group('classtype'),
                   'message': match.group('message'),
                   'source': match.group('src'),
                   'destination': match.group('dest'),
                   'protocol': match.group('protocol'),
                   }

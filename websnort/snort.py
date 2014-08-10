# Websnort - Web service for analysing pcap files with snort
# Copyright (C) 2014 Steve Henderson
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

from config import Config

STATUS_SUCCESS = "Success"
STATUS_FAILED = "Failed"

ALERT_PATTERN = re.compile(r"(?P<timestamp>\d{2}/\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
                           r"\[\*\*\]\s+\[\d+:(?P<sid>\d+):(?P<revision>\d+)\] "
                           r"(?P<message>.+) \[\*\*\]\s+\[Classification: (?P<classtype>.+)\] "
                           r"\[Priority: (?P<priority>\d+)\] \{(?P<protocol>\w+)\} "
                           r"(?P<src>.+) \-\> (?P<dest>.+)")

def snort_cmd(pcap):
    """Given a pcap filename, get the commandline to run.
    @param pcap: Pcap filename to scan
    @return: list of snort command args to scan supplied pcap file
    """
    config = Config()
    cmdline = "'{0}' -A console -N -y -c '{1}' -r '{2}'".format(config.path, config.rules, pcap)
    # can't seem to capture stderr from snort on win unless launched via cmd shell
    if 'nt' in os.name:
        cmdline = "cmd.exe /c " + cmdline 
    return shlex.split(cmdline)

def is_pcap(pcap):
    """Simple test for pcap magic bytes in supplied file.
    @param pcap: Pcap filename to check
    @return: True if content is pcap (magic bytes present), otherwise False.
    """
    with open(pcap, 'rb') as tmp:
        header = tmp.read(4)
        # check for both big/little endian
        if header == "\xa1\xb2\xc3\xd4" or \
           header == "\xd4\xc3\xb2\xa1":
            return True
        return False
     
def run(pcap, snortbin=None, conf=None):
    """Runs snort against the supplied pcap.
    @param snortbin: Path to snort binary (defaults to search PATH for 'snort')
    @param conf: Alternative location to snort/rules config file
    @param extra: List of extra arguments to run on snort command line
    @return: Dict with details/results of run
    """ 
    start = datetime.now()
    stdout = stderr = None
    status = STATUS_FAILED
    try:
        if not is_pcap(pcap):
            raise Exception("Not a valid pcap file")
  
        proc = Popen(snort_cmd(pcap), stdout=PIPE, stderr=PIPE, universal_newlines=True)
        stdout, stderr = proc.communicate() 
        if proc.returncode != 0:
            stderr = "\n".join(["Execution failed return code: {0}".format(proc.returncode),
                                stderr or ""])
        else:
            status = STATUS_SUCCESS
    except Exception, ex:
        stdout = ""
        stderr = str(ex)
        
    return {'start': start, 
            'duration': (datetime.now() - start).total_seconds(),
            'status': status, 
            'alerts': [ x for x in parse_alert(stdout) ], 
            'stderr': stderr,
            }

def parse_alert(output):
    """Parses the supplied output and yields any alerts.
    
    Example alert format:
    01/28/14-22:26:04.885446  [**] [1:1917:11] INDICATOR-SCAN UPnP service discover attempt [**] [Classification: Detection of a Network Scan] [Priority: 3] {UDP} 10.1.1.132:58650 -> 239.255.255.250:1900

    @param output: A file like object containing the output of running snort
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
    

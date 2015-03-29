# Websnort - Web service for analysing pcap files with snort
# Copyright (C) 2013-2014 Steve Henderson
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
from websnort.ids import snort

def test_parse_alert():
    count = 0
    for x in snort.parse_alert("01/28/14-22:26:04.885446 [**] [1:1917:11] INDICATOR-SCAN UPnP service discover attempt [**] [Classification: Detection of a Network Scan] [Priority: 3] {UDP} 10.1.1.132:58650 -> 239.255.255.250:1900\n"):
        assert x['message'] == "INDICATOR-SCAN UPnP service discover attempt"
        assert x['timestamp'] == datetime(2014, 01, 28, 22, 26, 04, 885446)
        assert x['classtype'] == "Detection of a Network Scan"
        assert x['sid'] == 1917
        assert x['revision'] == 11
        assert x['protocol'] == 'UDP'
        assert x['source'] == "10.1.1.132:58650"
        assert x['destination'] == "239.255.255.250:1900"
        count += 1
    assert count == 1

def test_parse_version():
    output = """
   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.6.0 GRE (Build 47) 
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/snort/snort-team
           Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.5.3
           Using PCRE version: 8.31 2012-07-06
           Using ZLIB version: 1.2.8
    """
    assert snort.parse_version(output) == "2.9.6.0 GRE (Build 47)"

if __name__ == '__main__':
    test_parse_alert()
    test_parse_version()


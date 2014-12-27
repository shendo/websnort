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
import time

from websnort import runner

def test_duration():
    start = datetime(2014, 1, 1, 0, 0, 0, 3245)
    end = datetime(2014, 1, 2, 0, 0, 0, 4245)
    assert runner.duration(start, end) == 86400.001
    assert runner.duration(end, start) == -86400.001
    end = start
    assert runner.duration(start, end) == 0
    start = datetime.now()
    time.sleep(0.5)
    assert runner.duration(start) >= 0.5

def test_run_ids():
    res = runner._run_ids(TestRunner(), None)
    assert res['version'] == '1.2.3-test'
    assert res['status'] == 'Success'
    assert len(res['alerts']) == 1
    assert res['alerts'][0]['message'] == 'test signature'


class TestRunner(runner.IDSRunner):

    def run(self, pcap):
        return ('1.2.3-test',
                [ {'timestamp': datetime(2014, 12, 1),
                   'sid': 1234,
                   'revision': 2,
                   'classtype': 'test',
                   'message': 'test signature',
                   'source': '1.2.3.4:5000',
                   'destination': '4.3.2.1:80',
                   'protocol': 'TCP',
                   } ])

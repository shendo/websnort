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
from multiprocessing.pool import ThreadPool

from websnort.plugins import registry
from websnort.config import Config

STATUS_SUCCESS = "Success"
STATUS_FAILED = "Failed"
MAX_THREADS = 3

def duration(start, end=None):
    """Returns duration in seconds since supplied time.
    @param start: datetime object
    @paaram end: Optional end datetime, None = now
    @return: Seconds as decimal since start
    """
    # time_delta.total_seconds() only available in 2.7+
    if not end:
        end = datetime.now()
    td = end - start
    return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 1000000) \
        / 1000000.0

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

def _run_ids(runner, pcap):
    """Runs the specified IDS runner.
    @param runner: Runner instance to use
    @param pcap: File path to pcap for analysis
    """
    run = {'name': runner.conf.get('name'),
           'module': runner.conf.get('module'),
           'ruleset': runner.conf.get('ruleset', 'default'),
           'status': STATUS_FAILED,
           }
    try:
        run_start = datetime.now()
        version, alerts = runner.run(pcap)
        run['version'] = version or 'Unknown'
        run['status'] = STATUS_SUCCESS
        run['alerts'] = alerts
    except Exception, ex:
        run['error'] = str(ex)
    finally:
        run['duration'] = duration(run_start)
    return run

def run(pcap):
    """Runs configured ids instances against the supplied pcap.
    @param pcap: File path to pcap file to analyse
    @return: Dict with details and results of run/s
    """
    start = datetime.now()
    errors = []
    status = STATUS_FAILED
    analyses = []
    pool = ThreadPool(MAX_THREADS)
    try:
        if not is_pcap(pcap):
            raise Exception("Not a valid pcap file")

        runners = []
        for conf in Config().modules.values():
            runner = registry.get(conf['module'])
            if not runner:
                raise Exception("No module named: '{0}' found registered"
                                .format(conf['module']))
            runners.append(runner(conf))
        # launch via worker pool
        analyses = [ pool.apply_async(_run_ids, (runner, pcap)) for runner in runners ]
        analyses = [ x.get() for x in analyses ]
        # were all runs successful?
        if all([ x['status'] == STATUS_SUCCESS for x in analyses ]):
            status = STATUS_SUCCESS
        # propagate any errors to the main list
        for run in [ x for x in analyses if x['status'] != STATUS_SUCCESS ]:
            errors.append("Failed to run {0}: {1}".format(run['name'], run['error']))
    except Exception, ex:
        errors.append(str(ex))

    return {'start': start,
            'duration': duration(start),
            'status': status,
            'analyses': analyses,
            'errors': errors,
            }

class IDSRunner(object):
    """Interface of IDS Runners."""

    conf = {}

    def run(self, pcap):
        """Run the IDS over the supplied pcap.
        @param pcap: File path to PCAP for anlaysis.
        @return: A tuple of version, alerts list.
        """
        pass

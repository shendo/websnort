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

from __future__ import absolute_import
from __future__ import unicode_literals

import pkg_resources

from websnort.ids import snort, suricata
# Mapping of known IDS module name -> Runner class
registry = {
    'snort': snort.Snort,
    'suricata': suricata.Suricata
}

for modules in pkg_resources.iter_entry_points(group='websnort.ids'):
    registry[modules.name] = modules.load()

class IDSRunner(object):

    def __init__(self, conf):
        """
        Interface for IDS Runners.

        :param conf: dict of config options for the given runner type.
        """
        self.conf = conf

    def run(self, pcap):
        """
        Run the IDS over the supplied pcap.

        :param pcap: File path to Pcap for analysis.
        :returns: A tuple of version, alerts list.
        """
        pass

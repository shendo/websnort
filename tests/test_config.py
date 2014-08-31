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

from websnort.config import Config

def test_config():
    conf = Config('websnort.conf.complex')
    assert len(conf.modules) == 3
    
    assert conf.modules.get('snort_community')
    assert conf.modules.get('snort_vrt')
    assert conf.modules.get('suricata_et')

    assert conf.modules['snort_community']['name'] == 'snort_community'
    assert conf.modules['snort_community']['module'] == 'snort'
    assert conf.modules['snort_community']['path'] == 'snort'
    assert conf.modules['snort_community']['ruleset'] == 'Community Rules'
    assert conf.modules['snort_community']['config'] == '/etc/snort/snort.conf'
    assert not conf.modules['snort_community']['extra_args']

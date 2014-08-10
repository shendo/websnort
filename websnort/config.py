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

from ConfigParser import ConfigParser
import os
from pkg_resources import DistributionNotFound, Requirement, ResourceManager

# path to conf files if package not installed
SOURCE_PATH = os.path.join(os.path.dirname(__file__), 'conf')

def installed_location(filename):
    """Returns the full path for the given installed file or None if not found.
    """
    try:
        return ResourceManager().resource_filename(Requirement.parse("websnort"), filename)
    except DistributionNotFound:
        return None
    
class Config:
    """Main config file parser for websnort.
    """
    def __init__(self, cfg='websnort.conf'):
        installed_path = installed_location(cfg) or 'notfound'
        parser = ConfigParser()
        parser.read([installed_path, os.path.join(SOURCE_PATH, cfg)])
        
        self.path = parser.get('snort', 'path')
        self.rules = parser.get('snort', 'config')
        

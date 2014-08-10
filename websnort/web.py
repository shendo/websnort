#!/usr/bin/env python

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

import argparse
from binascii import hexlify
from datetime import datetime
import hashlib
import json
import logging
import os
import tempfile

from bottle import request, response, route, run
from jinja2.environment import Environment
from jinja2.loaders import FileSystemLoader

from websnort import snort

# Load templates
root = os.path.join(os.path.dirname(__file__), "html")
env = Environment()
env.loader = FileSystemLoader(root)

jsondate = lambda obj: obj.isoformat() if isinstance(obj, datetime) else None
    
@route("/")
def home():
    """Main page, displays a submit file form"""
    template = env.get_template("submit.html")
    return template.render()

def run_snort(infile, filename):
    """Run snort across the supplied file.
    @param infile: File like object containing pcap data.
    @return: SnortRun object with results.
    """
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    m = hashlib.md5()
    results = {'filename': filename,
               'status': 'Failed',
               }
    try:
        size = 0        
        while True:
            buf = infile.read(16384)
            if not buf: break
            tmp.write(buf)
            size += len(buf)
            m.update(buf)
        tmp.close()
        results['md5'] = hexlify(m.digest())
        results['filesize'] = size
        results.update(snort.run(tmp.name))
    except OSError, ex:
        results['stderr'] = str(ex)
    finally:
        os.remove(tmp.name)
    return results

@route("/submit", method="POST")
def submit_and_render():
    """Blocking POST handler for file submission.
    Runs snort on supplied file and returns results."""
    data = request.files.file
    template = env.get_template("results.html")
    if not data:
        pass
    
    return template.render(run_snort(data.file, data.filename))

@route("/api/submit", method="POST")
def api_submit():
    """Blocking POST handler for file submission.
    Runs snort on supplied file and returns results."""
    data = request.files.file
    response.content_type = 'application/json'
    if not data or not hasattr(data, 'file'):
        return json.dumps({"status": "Failed", "stderr": "Missing form params"})
    return json.dumps(run_snort(data.file, data.filename), default=jsondate)
    
@route("/api")
def api():
    template = env.get_template("api.html")
    return template.render()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Web server Host address to bind to", 
                        default="0.0.0.0", action="store", required=False)
    parser.add_argument("-p", "--port", help="Web server Port to bind to", 
                        default=8080, action="store", required=False)
    args = parser.parse_args()
    
    logging.basicConfig()
    run(host=args.host, port=args.port, reloader=True)

if __name__ == '__main__':
    main()
    

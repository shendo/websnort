#!/usr/bin/env python

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

try:
    from gevent import monkey
    monkey.patch_all()
    SERVER = 'gevent'
except ImportError:
    SERVER = 'wsgiref'

import argparse
from datetime import datetime
import hashlib
import json
import logging
import os
import tempfile

from bottle import request, response, route, run, default_app
from jinja2.environment import Environment
from jinja2.loaders import FileSystemLoader

from websnort import runner
from websnort.version import __version__

# Load templates
root = os.path.join(os.path.dirname(__file__), "html")
env = Environment()
env.loader = FileSystemLoader(root)

jsondate = lambda obj: obj.isoformat() if isinstance(obj, datetime) else None

@route("/", name="home")
def home():
    """
    Main page, displays a submit file form.
    """
    template = env.get_template("submit.html")
    return template.render(base)

def analyse_pcap(infile, filename):
    """
    Run IDS across the supplied file.

    :param infile: File like object containing pcap data.
    :param filename: Filename of the submitted file.
    :returns: Dictionary of analysis results.
    """
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    m = hashlib.md5()
    results = {'filename': filename,
               'status': 'Failed',
               'apiversion': __version__,
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
        results['md5'] = m.hexdigest()
        results['filesize'] = size
        results.update(runner.run(tmp.name))
    except OSError as ex:
        results['stderr'] = str(ex)
    finally:
        os.remove(tmp.name)
    return results

@route("/submit", method="POST", name="submit")
def submit_and_render():
    """
    Blocking POST handler for file submission.
    Runs snort on supplied file and returns results as rendered html.
    """
    data = request.files.file
    template = env.get_template("results.html")
    if not data:
        pass
    results = analyse_pcap(data.file, data.filename)
    results.update(base)
    return template.render(results)

@route("/api/submit", method="POST", name="api_submit")
def api_submit():
    """
    Blocking POST handler for file submission.
    Runs snort on supplied file and returns results as json text.
    """
    data = request.files.file
    response.content_type = 'application/json'
    if not data or not hasattr(data, 'file'):
        return json.dumps({"status": "Failed", "stderr": "Missing form params"})
    return json.dumps(analyse_pcap(data.file, data.filename), default=jsondate, indent=4)

@route("/api", name="api")
def api():
    """
    Display an api usage/help page.
    """
    template = env.get_template("api.html")
    return template.render(base)


def main():
    """
    Main entrypoint for command-line webserver.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Web server Host address to bind to",
                        default="0.0.0.0", action="store", required=False)
    parser.add_argument("-p", "--port", help="Web server Port to bind to",
                        default=8080, action="store", required=False)
    args = parser.parse_args()

    logging.basicConfig()
    run(host=args.host, port=args.port, reloader=True, server=SERVER)

# WSGI and template url support
application = default_app()
base = {'get_url': application.get_url}

if __name__ == '__main__':
    main()

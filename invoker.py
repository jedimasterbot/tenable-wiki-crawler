from configparser import ConfigParser
import json
from urllib.parse import urlparse

from flask import Flask, render_template, request

from scripts.tenableScraper import ScrapWithID

app = Flask(__name__)
app.jinja_options['extensions'].append('jinja2.ext.loopcontrols')

config_object = ConfigParser()
config_object.read("config.ini")


@app.route('/')
def url():
    return render_template('urlsubmit.html')


@app.route('/validate', methods=['POST'])
def validate():
    if request.method == 'POST':
        url = request.form.get('url')
        if not url.startswith("http") or not url.startswith("https"):
            url = "https://" + url

        url_parsing = urlparse(url)
        domain = url_parsing.netloc
        path = url_parsing.path
        sp_paths = path.split('/')
        family_list = ['nessus', 'was', 'lce', 'nnm']

        if domain == "www.tenable.com":

            if sp_paths[1] == 'plugins' and sp_paths[2] in family_list:

                data = ScrapWithID(url).__getattribute__("data")
                response = json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))

                return render_template("result.html", result=response)

            else:
                return render_template("empty.html", result="WRONG PATH!!!")

        else:
            return render_template("empty.html", result="WRONG DOMAIN!!!")


if __name__ == '__main__':
    host_server = config_object["SERVER"]["HOST"]
    host_port = config_object["SERVER"]["PORT"]
    app.run(host=host_server, port=host_port, debug=True)

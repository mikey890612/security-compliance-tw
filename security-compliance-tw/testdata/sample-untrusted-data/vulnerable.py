import pickle
from xml.etree import ElementTree as ET

import yaml
from flask import Flask, redirect, request
from lxml import etree

app = Flask(__name__)


@app.route("/login/done")
def login_done():
    return redirect(request.args.get("next", "/"))


@app.route("/import/session", methods=["POST"])
def import_session():
    state = pickle.loads(request.get_data())
    return {"keys": sorted(state)}


@app.route("/import/config", methods=["POST"])
def import_config():
    cfg = yaml.load(request.get_data(), Loader=yaml.Loader)
    return {"keys": sorted(cfg)}


@app.route("/import/xml", methods=["POST"])
def import_xml():
    root = ET.fromstring(request.get_data())
    return {"tag": root.tag}


@app.route("/import/lxml", methods=["POST"])
def import_lxml():
    parser = etree.XMLParser(resolve_entities=True)
    root = etree.fromstring(request.get_data(), parser)
    return {"tag": root.tag}


@app.route("/preference")
def preference():
    resp = app.make_response(("", 204))
    resp.headers["Set-Cookie"] = "theme=" + request.args.get("theme", "") + "; Path=/"
    return resp

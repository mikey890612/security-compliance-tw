import json
from urllib.parse import urlsplit, urlunsplit

import defusedxml.ElementTree as DET
import yaml
from flask import Flask, redirect, request

app = Flask(__name__)

ALLOWED_THEMES = {"light", "dark"}


def safe_next(raw):
    parts = urlsplit(raw or "")
    target = urlunsplit(("", "", parts.path, parts.query, ""))
    if parts.scheme or parts.netloc or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return "/"
    return target


@app.route("/v2/login/done")
def login_done_fixed():
    target = safe_next(request.args.get("next", "/"))
    return redirect(target)


@app.route("/v2/import/session", methods=["POST"])
def import_session_fixed():
    state = json.loads(request.get_data())
    return {"keys": sorted(state)}


@app.route("/v2/import/config", methods=["POST"])
def import_config_fixed():
    cfg = yaml.safe_load(request.get_data())
    return {"keys": sorted(cfg)}


@app.route("/v2/import/xml", methods=["POST"])
def import_xml_fixed():
    root = DET.fromstring(request.get_data())
    return {"tag": root.tag}


@app.route("/v2/preference")
def preference_fixed():
    theme = request.args.get("theme", "")
    if theme not in ALLOWED_THEMES:
        theme = "light"
    resp = app.make_response(("", 204))
    resp.set_cookie("theme", theme, path="/", secure=True, httponly=True, samesite="Lax")
    return resp

import pathlib
import ssl
from threading import Thread

import sanic
from blackburn import load_json_file
from sanic import Sanic, response
from sanic_jwt import Initialize, exceptions, decorators
from sanic_openapi import doc, openapi2_blueprint

import inntinn

"""api: Inntinn scoring and data access API"""

__author__ = "Brandon Blackburn"
__maintainer__ = "Brandon Blackburn"
__email__ = "contact@bhax.net"
__website__ = "https://keybase.io/blackburnhax"
__copyright__ = "Copyright 2021 Brandon Blackburn"
__license__ = "Apache 2.0"

#  Copyright (c) 2021. Brandon Blackburn - https://keybase.io/blackburnhax, Apache License, Version 2.0.
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  http://www.apache.org/licenses/LICENSE-2.0
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
#  either express or implied. See the License for the specific
#  language governing permissions and limitations under the License.
#  TL;DR:
#  For a human-readable & fast explanation of the Apache 2.0 license visit:  http://www.tldrlegal.com/l/apache2

# region JWT Authentication
config_file = load_json_file(pathlib.Path.cwd().parent / "config.json")


class User:
    def __init__(self, id, username, password):
        self.user_id = id
        self.username = username
        self.password = password

    def __repr__(self):
        return "User(id='{}')".format(self.user_id)

    def to_dict(self):
        return {"user_id": self.user_id, "username": self.username}


users = [User(1, "admin", config_file["inntinn_api"]["admin_pass"])]

username_table = {u.username: u for u in users}
userid_table = {u.user_id: u for u in users}


async def authenticate(request, *args, **kwargs):
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    if not username or not password:
        raise exceptions.AuthenticationFailed("Invalid username or password.")

    user = username_table.get(username, None)
    if user is None:
        raise exceptions.AuthenticationFailed("User not found.")

    if password != user.password:
        raise exceptions.AuthenticationFailed("Password is incorrect.")

    return user


# endregion JWT Authentication


app = Sanic("Inntinn")
http = Sanic("HTTP Proxy")
app.ctx.db = inntinn.Database(pathlib.Path.cwd().parent / "config.json", tls=False)
app.ctx.config = load_json_file(pathlib.Path.cwd().parent / "config.json")
app.blueprint(openapi2_blueprint)
Initialize(app, authenticate=authenticate)

tls_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
http_port = 80
https_port = 443
public_cert = pathlib.Path(app.ctx.config["inntinn_api"]["tls_cert"]).resolve()
private_key = pathlib.Path(app.ctx.config["inntinn_api"]["tls_key"]).resolve()
tls_context.load_cert_chain(public_cert, keyfile=private_key)

app.config.SERVER_NAME = "127.0.0.1"
http.config.SERVER_NAME = "Redirect"
app.static("/favicon.ico", pathlib.Path.cwd() / "favicon.ico")
http.static("/favicon.ico", pathlib.Path.cwd() / "favicon.ico")


# region Swagger Spec definitions
class ScoringObjectOrg:
    scores = doc.List(doc.Integer("Individual Inntinn device-level scores"))


class ScoringObject:
    company = doc.String("Company name or CIK")
    cves = doc.List(doc.String("List of CVEs which apply to this device"))


class LookupStr:
    lookup = str


class AdminObject:
    Authorization = doc.String("Format 'Bearer YOUR_JWT' JWT obtained from /auth")


found_ciks = {int: doc.String("Company names")}


class FoundCVE:
    _id = doc.String("CVE ID")
    description = doc.String("NIST provided vulnerability description")
    obtainAllPrivilege = bool
    obtainOtherPrivilege = bool
    obtainUserPrivilege = bool
    userInteractionRequired = bool
    references = [doc.String("URLs to relevant NIST supplied documentation")]
    v2_score = doc.Float("CVSS v2 Score (-1 if unavailable)")
    v3_score = doc.Float("CVSS v3 Score (-1 if unavailable)")


class ScoredObject:
    score = doc.Integer("1-100 Inntinn Device-level score (100 being greatest risk)")
    confidence = doc.Integer(
        "1-100 Level of certainty that the score reflects reality. (Omitted in case of CIK scoring)"
    )


class ScoredObjectOrg:
    org_score = doc.Integer("Inntinn Organizational-level score")


# endregion Swagger Spec definitions

# region HTTP to HTTPS redirection
@http.get("/<path:path>")
def proxy(request, path):
    """
    Seamless HTTP to HTTPS pass-through
    :param request: request object
    :param path: path object
    :return: redirects to the equivalent HTTPS handler
    """
    url = request.app.url_for(
        "proxy",
        path=path,
        _server=app.config.SERVER_NAME,
        _external=True,
        _scheme="https",
    )
    return response.redirect(url)


@app.before_server_start
async def start(app, _):
    global http
    app.http_server = await http.create_server(
        port=http_port, return_asyncio_server=True
    )
    app.http_server.after_start()


@app.before_server_stop
async def stop(app, _):
    app.http_server.before_stop()
    await app.http_server.close()
    app.http_server.after_stop()


# endregion HTTP to HTTPS redirection

# region Standardized response builders
def api_error(error_message: str, status_code: int) -> sanic.response:
    """
    Builds a response payload in the format {"message": your_message} with the provided error status code
    :param error_message: The error message to send
    :param status_code: HTTP status code to send
    :return: Returns a Sanic response object
    """
    assert isinstance(status_code, int), "status_code must be an integer"
    assert isinstance(error_message, str), "error_message must be a string"
    assert status_code >= 400, "status code must be an error code at or above 400"
    assert status_code <= 511, "status code must be an error code at or below 511"
    return response.json(
        {"message": f"{error_message}".strip().lower()},
        headers={"X-Served-By": "Inntinn"},
        status=status_code,
    )


def api_message(status_message: str, status_code: int) -> sanic.response:
    """
    Builds a response payload in the format {"message": your_message} with the provided status code
    :param status_message: The status message to send
    :param status_code: HTTP status code to send
    :return: Returns a Sanic response object
    """
    assert isinstance(status_code, int), "status_code must be an integer"
    assert isinstance(status_message, str), "status_message must be a string"
    assert status_code < 300, "status code must be a code below 300"
    assert status_code >= 200, "status code must be a code at or above 100"
    return response.json(
        {"message": f"{status_message}".strip().lower()},
        headers={"X-Served-By": "Inntinn"},
        status=status_code,
    )


def api_json(payload: dict, status_code: int) -> sanic.response:
    """
    Builds a response payload using the supplied dictionary with the provided status code
    :param payload: The JSON payload to send (passed to this function as a dictionary)
    :param status_code: HTTP status code to send
    :return: Returns a Sanic response object
    """
    assert isinstance(status_code, int), "status_code must be an integer"
    assert isinstance(payload, dict), "payload must be a dictionary"
    assert status_code < 511, "status code must be a code below 511"
    assert status_code >= 200, "status code must be a code at or above 100"
    return response.json(
        payload,
        headers={"X-Served-By": "Inntinn"},
        status=status_code,
    )


# endregion Standardized response builders


@app.get("/")
@doc.exclude(True)
async def handler_root(request: sanic.Request):
    return api_message("Ready", 200)


@app.get("/api/license/timestamp/*")
@doc.exclude(True)
async def handler_root(request: sanic.Request):
    return api_message("Ready", 200)


@app.route("/server", methods=["POST"])
@doc.summary(
    "Updates all internal databases using freshly downloaded data, REQUIRES JWT Auth"
)
@doc.consumes(AdminObject, location="headers")
@decorators.protected()
async def handler_server(request: sanic.Request):
    if request.method == "POST":
        Thread(target=app.ctx.db.update).start()
        return api_message("Processing update", 202)


@app.route("/cik", methods=["POST"])
@doc.summary("Looks up all matching companies given the supplied company name")
@doc.consumes(LookupStr, location="body")
@doc.produces(found_ciks)
async def handler_cik(request: sanic.Request):
    try:
        returned_data = api_json(app.ctx.db.cik_lookup(request.json["lookup"]), 200)
    except sanic.exceptions.InvalidUsage:
        returned_data = api_error(
            "format must be a JSON with format {'lookup':company_name_here}", 400
        )
    return returned_data


@app.route("/cve", methods=["POST"])
@doc.summary("Retrieve available information on a given NVD CVE ID")
@doc.consumes(LookupStr, location="body")
@doc.produces(FoundCVE)
async def handler_cve(request: sanic.Request):
    try:
        return api_json(app.ctx.db.cve_lookup(request.json["lookup"]), 200)
    except sanic.exceptions.InvalidUsage:
        return api_error("format must be a JSON with format {'lookup':CVE here}", 400)
    except ValueError:
        return api_error(
            "CVE ID must confirm to NIST NVD standards, only 1 CVE is allowed per request",
            400,
        )


@app.route("/score", methods=["POST"])
@doc.summary(
    "Calculate a final score for a given device which is vulnerable to the list of CVEs and is found in the company identified by CIK or partial name match"
)
@doc.consumes(ScoringObject, location="body")
@doc.produces(ScoredObject)
async def handler_score(request: sanic.Request):
    def format_error():
        return api_error(
            "format must be a JSON with format {'cves':CVE_list_here, 'company':company_name_or_cik}",
            400,
        )

    try:
        cves = request.json["cves"]
        company = request.json["company"]
    except sanic.exceptions.InvalidUsage:
        return format_error()
    if not isinstance(cves, list):
        return format_error()
    if not isinstance(company, (int, str)):
        return format_error()
    try:
        company = int(company)
        fuzzy = False
    except ValueError:
        fuzzy = True

    if fuzzy:
        result = app.ctx.db.score_device_list_fuzzy(cves, company)
        if result[1] < 1:
            status_code = 404
        else:
            status_code = 200
        return api_json({"score": result[0], "confidence": result[1]}, status_code)
    else:
        try:
            result = app.ctx.db.score_device_list(cves, company)
        except LookupError:
            return api_json({"score": -1}, 404)
        return api_json({"score": result}, 200)


@app.route("/score/org", methods=["POST"])
@doc.summary(
    "Creates a single company-wide score that can measure overall risk in relation to other companies, or over time."
)
@doc.consumes(ScoringObjectOrg, location="body")
@doc.produces(ScoredObjectOrg)
async def handler_score_org(request: sanic.Request):
    def format_error():
        return api_error(
            "format must be a JSON with format {'scores':[Inntinn_score_list]} - Scores must be integers, not strings",
            400,
        )

    try:
        scores = request.json["scores"]
    except sanic.exceptions.InvalidUsage:
        return format_error()
    if not isinstance(scores, list):
        return format_error()
    try:
        result = app.ctx.db.score_org(scores)
    except TypeError:
        return format_error()
    payload = {"org_score": result}
    return api_json(payload, 200)


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        debug=True,
        access_log=False,
        port=https_port,
        workers=10,
        ssl=tls_context,
    )

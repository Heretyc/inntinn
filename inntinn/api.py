import ssl
from sanic import Sanic, response
from sanic.response import text
import inntinn
import pathlib

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

tls_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)

http_port = 80
https_port = 443
public_cert = pathlib.Path("snakeoil_cert.pem").resolve()
private_key = pathlib.Path("snakeoil_key.pem").resolve()
tls_context.load_cert_chain(public_cert, keyfile=private_key)

app = Sanic("Inntinn")
http = Sanic("HTTP Proxy")
app.ctx.db = inntinn.Database(pathlib.Path.cwd().parent / "config.json", tls=False)

app.config.SERVER_NAME = "127.0.0.1"
http.config.SERVER_NAME = "Redirect"
app.static("/favicon.ico", pathlib.Path.cwd() / "favicon.ico")
http.static("/favicon.ico", pathlib.Path.cwd() / "favicon.ico")


# region HTTP to HTTPS redirection
@http.get("/<path:path>")
def http_redirect(request, path):
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


@app.get("/")
async def root(request):
    return text("Server Ready")


@app.route("/test", methods=["POST", "PUT", "GET"])
async def handler(request):
    return text("OK")


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        debug=False,
        access_log=False,
        port=https_port,
        workers=10,
        ssl=tls_context,
    )

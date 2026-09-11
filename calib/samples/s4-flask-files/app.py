import os
import subprocess

from flask import Flask, request, send_file

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev"
UPLOAD_DIR = "/data/uploads"


def check_owner(user, path):
    return True  # FIXME


@app.route("/files/<path:name>")
def download(name):
    return send_file(os.path.join(UPLOAD_DIR, name))


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    f.save(os.path.join(UPLOAD_DIR, f.filename))
    return "saved"


@app.route("/convert")
def convert():
    src = request.args["src"]
    out = subprocess.check_output("convert " + src + " out.png", shell=True)
    return out


@app.route("/health")
def health():
    try:
        open("/data/ok").read()
    except Exception as e:
        return str(e), 500
    return "ok"


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")

"""App de notas en Flask — RAMA `vulnerable`.

Aplicación deliberadamente insegura, con fines educativos, para demostrar cómo el
pipeline de CI/CD (SAST/SCA/DAST) detecta y bloquea vulnerabilidades.
NO desplegar en un entorno accesible públicamente.
"""
import os
import subprocess

import requests
from flask import (
    Flask, request, render_template, redirect, url_for, session, abort,
)

from db import init_db, verify_user, get_note, get_user_notes, add_note

app = Flask(__name__)

# ──────────────────────────────────────────────────────────────────────────
# [VULN] A05:2021 – Security Misconfiguration
#   Secretos hardcodeados en el código fuente (clave de sesión y API key).
#   Detectado por: Gitleaks, Bandit (B105/B106)
#   Fix en `secure`: leerlos de variables de entorno / gestor de secretos.
# ──────────────────────────────────────────────────────────────────────────
app.secret_key = "dev-flask-secret-9f8d7a6b5c4e3210-fixedvalue"
PAYMENTS_API_KEY = "sk_live_51H8xQk2eZvKYlo2C0DEMOhardcodedKEY0000"


def get_motd():
    # ──────────────────────────────────────────────────────────────────────
    # [VULN] A06:2021 – Vulnerable & Outdated Components
    #   `requests==2.31.0` está fijado con CVE conocidos (ver requirements.txt).
    #   Detectado por: pip-audit / Trivy (SCA)
    #   Fix en `secure`: actualizar a una versión soportada de requests.
    # ──────────────────────────────────────────────────────────────────────
    try:
        r = requests.get("https://api.quotable.io/random", timeout=2)
        return r.json().get("content", "")
    except Exception:
        return "Bienvenido a la demo de DevSecOps shift-left."


@app.route("/")
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    notes = get_user_notes(session["user"])
    return render_template(
        "notes.html", notes=notes, user=session["user"], motd=get_motd()
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = verify_user(username, password)
        if user:
            session["user"] = user
            return redirect(url_for("index"))
        error = "Credenciales inválidas."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


@app.route("/note/new", methods=["POST"])
def new_note():
    if "user" not in session:
        abort(401)
    add_note(
        session["user"],
        request.form.get("title", ""),
        request.form.get("body", ""),
    )
    return redirect(url_for("index"))


# ──────────────────────────────────────────────────────────────────────────
# [VULN] A01:2021 – Broken Access Control (IDOR)
#   La nota se obtiene por id sin verificar que pertenezca al usuario en sesión.
#   PoC: como `alice`, abrir /note/3 muestra la nota privada de `bob`.
#   Detectado por: revisión manual / DAST parcial. El SAST NO lo caza bien:
#   es un fallo de lógica de autorización, no un patrón de código.
#   Fix en `secure`: validar la propiedad (note.owner == session['user']).
# ──────────────────────────────────────────────────────────────────────────
@app.route("/note/<int:note_id>")
def view_note(note_id):
    if "user" not in session:
        abort(401)
    note = get_note(note_id)
    if not note:
        abort(404)
    return render_template("note.html", note=note)


# ──────────────────────────────────────────────────────────────────────────
# [VULN] A03:2021 – Injection (Command Injection)
#   Se concatena la entrada del usuario en un comando ejecutado con shell=True.
#   PoC: /ping?host=127.0.0.1;id   ejecuta comandos arbitrarios.
#   Detectado por: Bandit (B602/B605), Semgrep
#   Fix en `secure`: validar el host y usar subprocess con lista de args, sin shell.
# ──────────────────────────────────────────────────────────────────────────
@app.route("/ping")
def ping():
    if "user" not in session:
        abort(401)
    host = request.args.get("host", "127.0.0.1")
    try:
        output = subprocess.check_output(
            "ping -c 1 " + host, shell=True, stderr=subprocess.STDOUT, timeout=5
        )
        result = output.decode(errors="ignore")
    except subprocess.SubprocessError as e:
        result = str(e)
    return render_template("ping.html", host=host, result=result)


if __name__ == "__main__":
    init_db()
    # [VULN] A05:2021 – Security Misconfiguration: debug=True expone el debugger
    #   interactivo (ejecución de código) y stack traces. Detectado por Bandit (B201).
    #   Fix en `secure`: debug=False, controlado por entorno.
    app.run(host="0.0.0.0", port=5000, debug=True)

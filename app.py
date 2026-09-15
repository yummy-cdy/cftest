import sqlite3
from pathlib import Path

from flask import Flask, g, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

DB_PATH = Path(__file__).parent / "app.db"

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-me"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
            """
        )
        db.commit()


BASE_TEMPLATE = """
<!doctype html>
<html>
<head>
<title>{{ title }}</title>
<style>
  body { font-family: sans-serif; max-width: 420px; margin: 60px auto; padding: 0 16px; color: #222; }
  nav { margin-bottom: 20px; }
  nav a { margin-right: 8px; }
  h1 { font-size: 20px; }
  input { display: block; margin: 8px 0; padding: 6px; width: 100%; box-sizing: border-box; }
  input[type=submit] { width: auto; padding: 6px 16px; cursor: pointer; }
  .error { color: #c0392b; }
  hr { border: none; border-top: 1px solid #ddd; margin: 20px 0; }
</style>
</head>
<body>
<nav>
{% if session.get('username') %}
    <span>{{ session['username'] }}님 환영합니다.</span> <a href="{{ url_for('logout') }}">로그아웃</a>
{% else %}
    <a href="{{ url_for('login') }}">로그인</a> <a href="{{ url_for('signup') }}">회원가입</a>
{% endif %}
</nav>
<hr>
{% if error %}
    <p class="error">{{ error }}</p>
{% endif %}
{{ body|safe }}
</body>
</html>
"""


@app.route("/")
def index():
    body = "<h1>메인 페이지</h1>"
    return render_template_string(BASE_TEMPLATE, title="홈", body=body, error=None)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            error = "아이디와 비밀번호를 모두 입력해주세요."
        else:
            db = get_db()
            existing = db.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if existing:
                error = "이미 존재하는 아이디입니다."
            else:
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
                return redirect(url_for("login"))

    body = """
    <h1>회원가입</h1>
    <form method="post">
        아이디: <input type="text" name="username"><br>
        비밀번호: <input type="password" name="password"><br>
        <input type="submit" value="가입하기">
    </form>
    """
    return render_template_string(BASE_TEMPLATE, title="회원가입", body=body, error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            error = "아이디 또는 비밀번호가 올바르지 않습니다."
        else:
            session["username"] = user["username"]
            return redirect(url_for("index"))

    body = """
    <h1>로그인</h1>
    <form method="post">
        아이디: <input type="text" name="username"><br>
        비밀번호: <input type="password" name="password"><br>
        <input type="submit" value="로그인">
    </form>
    """
    return render_template_string(BASE_TEMPLATE, title="로그인", body=body, error=error)


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)

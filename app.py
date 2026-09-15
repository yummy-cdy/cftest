import sqlite3
from functools import wraps
from pathlib import Path

from flask import Flask, g, redirect, render_template_string, request, session, url_for
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

DB_PATH = Path(__file__).parent / "app.db"

# 데모용 초기 admin 계정 / 시드 메모 - 운영 환경에서는 반드시 값을 변경하세요.
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin1234!"
ADMIN_FLAG = "SBOB{admin_only_memo_flag}"

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
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS memos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """
        )
        db.commit()

        admin = db.execute(
            "SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,)
        ).fetchone()
        if admin is None:
            cur = db.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
                (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD)),
            )
            admin_id = cur.lastrowid
            db.execute(
                "INSERT INTO memos (user_id, title, content) VALUES (?, ?, ?)",
                (admin_id, "관리자 전용 메모", ADMIN_FLAG),
            )
            db.commit()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        db = get_db()
        row = db.execute(
            "SELECT is_admin FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        if not row or not row["is_admin"]:
            return "권한이 없습니다.", 403
        return view(*args, **kwargs)

    return wrapped


BASE_TEMPLATE = """
<!doctype html>
<html>
<head>
<title>{{ title }}</title>
<style>
  body { font-family: sans-serif; max-width: 480px; margin: 60px auto; padding: 0 16px; color: #222; }
  nav { margin-bottom: 20px; }
  nav a { margin-right: 8px; }
  h1 { font-size: 20px; }
  input, textarea { display: block; margin: 8px 0; padding: 6px; width: 100%; box-sizing: border-box; font: inherit; }
  input[type=submit] { width: auto; padding: 6px 16px; cursor: pointer; }
  .error { color: #c0392b; }
  hr { border: none; border-top: 1px solid #ddd; margin: 20px 0; }
  table { border-collapse: collapse; }
  td, th { padding: 4px 8px; }
</style>
</head>
<body>
<nav>
{% if session.get('username') %}
    <span>{{ session['username'] }}님 환영합니다.</span>
    <a href="{{ url_for('memo_list') }}">메모</a>
    {% if session.get('is_admin') %}
    <a href="{{ url_for('admin_users') }}">관리자</a>
    {% endif %}
    <a href="{{ url_for('logout') }}">로그아웃</a>
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
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
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
    session.clear()
    return redirect(url_for("index"))


@app.route("/memos")
@login_required
def memo_list():
    db = get_db()
    memos = db.execute(
        "SELECT id, title, created_at FROM memos WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],),
    ).fetchall()
    items = "".join(
        '<li><a href="{}">{}</a> <small>({})</small></li>'.format(
            url_for("memo_detail", memo_id=m["id"]), escape(m["title"]), m["created_at"]
        )
        for m in memos
    ) or "<li>메모가 없습니다.</li>"
    body = """
    <h1>내 메모</h1>
    <p><a href="{new_url}">새 메모 작성</a></p>
    <ul>{items}</ul>
    """.format(new_url=url_for("memo_new"), items=items)
    return render_template_string(BASE_TEMPLATE, title="메모 목록", body=body, error=None)


@app.route("/memos/new", methods=["GET", "POST"])
@login_required
def memo_new():
    error = None
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        if not title or not content:
            error = "제목과 내용을 모두 입력해주세요."
        else:
            db = get_db()
            db.execute(
                "INSERT INTO memos (user_id, title, content) VALUES (?, ?, ?)",
                (session["user_id"], title, content),
            )
            db.commit()
            return redirect(url_for("memo_list"))

    body = """
    <h1>새 메모</h1>
    <form method="post">
        제목: <input type="text" name="title" value="{title}"><br>
        내용: <textarea name="content" rows="6">{content}</textarea><br>
        <input type="submit" value="저장">
    </form>
    """.format(
        title=escape(request.form.get("title", "")),
        content=escape(request.form.get("content", "")),
    )
    return render_template_string(BASE_TEMPLATE, title="새 메모", body=body, error=error)


def _get_own_memo(memo_id):
    db = get_db()
    memo = db.execute("SELECT * FROM memos WHERE id = ?", (memo_id,)).fetchone()
    if memo is None or memo["user_id"] != session["user_id"]:
        return None
    return memo


@app.route("/memos/<int:memo_id>")
@login_required
def memo_detail(memo_id):
    memo = _get_own_memo(memo_id)
    if memo is None:
        return "메모를 찾을 수 없습니다.", 404

    body = """
    <h1>{title}</h1>
    <pre>{content}</pre>
    <p>
        <a href="{edit_url}">수정</a>
        <form method="post" action="{delete_url}" style="display:inline">
            <input type="submit" value="삭제" onclick="return confirm('삭제하시겠습니까?')">
        </form>
    </p>
    <p><a href="{list_url}">목록으로</a></p>
    """.format(
        title=escape(memo["title"]),
        content=escape(memo["content"]),
        edit_url=url_for("memo_edit", memo_id=memo["id"]),
        delete_url=url_for("memo_delete", memo_id=memo["id"]),
        list_url=url_for("memo_list"),
    )
    return render_template_string(BASE_TEMPLATE, title=memo["title"], body=body, error=None)


@app.route("/memos/<int:memo_id>/edit", methods=["GET", "POST"])
@login_required
def memo_edit(memo_id):
    memo = _get_own_memo(memo_id)
    if memo is None:
        return "메모를 찾을 수 없습니다.", 404

    error = None
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        if not title or not content:
            error = "제목과 내용을 모두 입력해주세요."
        else:
            db = get_db()
            db.execute(
                "UPDATE memos SET title = ?, content = ? WHERE id = ? AND user_id = ?",
                (title, content, memo_id, session["user_id"]),
            )
            db.commit()
            return redirect(url_for("memo_detail", memo_id=memo_id))

    body = """
    <h1>메모 수정</h1>
    <form method="post">
        제목: <input type="text" name="title" value="{title}"><br>
        내용: <textarea name="content" rows="6">{content}</textarea><br>
        <input type="submit" value="수정">
    </form>
    """.format(
        title=escape(request.form.get("title", memo["title"])),
        content=escape(request.form.get("content", memo["content"])),
    )
    return render_template_string(BASE_TEMPLATE, title="메모 수정", body=body, error=error)


@app.route("/memos/<int:memo_id>/delete", methods=["POST"])
@login_required
def memo_delete(memo_id):
    memo = _get_own_memo(memo_id)
    if memo is None:
        return "메모를 찾을 수 없습니다.", 404

    db = get_db()
    db.execute(
        "DELETE FROM memos WHERE id = ? AND user_id = ?", (memo_id, session["user_id"])
    )
    db.commit()
    return redirect(url_for("memo_list"))


@app.route("/admin")
@admin_required
def admin_users():
    db = get_db()
    users = db.execute("SELECT id, username, is_admin FROM users ORDER BY id").fetchall()
    rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            u["id"], escape(u["username"]), "admin" if u["is_admin"] else ""
        )
        for u in users
    )
    body = """
    <h1>관리자 - 전체 회원 목록</h1>
    <table border="1">
        <tr><th>ID</th><th>아이디</th><th>권한</th></tr>
        {rows}
    </table>
    """.format(rows=rows)
    return render_template_string(BASE_TEMPLATE, title="관리자 페이지", body=body, error=None)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)

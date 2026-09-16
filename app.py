import logging
import os
import secrets
import sqlite3
import stat
import time
from collections import defaultdict
from datetime import timedelta
from functools import wraps
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, g, jsonify, redirect, render_template_string, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError, generate_csrf
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
security_logger = logging.getLogger("cf.security")

# 컨테이너에서는 CF_DATA_DIR을 볼륨 마운트 경로(예: /app/data)로 지정해 DB가
# 컨테이너 재생성 후에도 유지되도록 한다. 로컬 개발 시에는 app.py 옆에 저장된다.
DATA_DIR = Path(os.environ.get("CF_DATA_DIR", Path(__file__).parent))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "app.db"

# 운영 배포 시 CF_ENV=production 으로 설정하면 디버거가 꺼지고 쿠키에 Secure 플래그가 붙는다.
IS_PRODUCTION = os.environ.get("CF_ENV", "development") == "production"

# Docker 이미지 빌드 시 생성되는 파일(Dockerfile 참고). 배포가 실제로 서버에 반영됐는지
# 확인할 수 있도록 화면 구석에 표시한다. 로컬에서 python app.py로 직접 띄우면 없으므로 "dev"로 표시.
_BUILD_INFO_PATH = Path(__file__).parent / "BUILD_INFO"
BUILD_INFO = _BUILD_INFO_PATH.read_text().strip() if _BUILD_INFO_PATH.exists() else "dev (no BUILD_INFO)"

# 비밀 값은 .env(버전관리 제외)나 환경변수로 주입한다. 아래 기본값은 로컬 개발용으로만 사용할 것.
_DEV_DEFAULT_SECRET_KEY = "dev-only-insecure-secret-set-CF_SECRET_KEY-env-var"
_DEV_DEFAULT_ADMIN_PASSWORD = "admin1234!"
SECRET_KEY = os.environ.get("CF_SECRET_KEY", _DEV_DEFAULT_SECRET_KEY)
ADMIN_USERNAME = os.environ.get("CF_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("CF_ADMIN_PASSWORD", _DEV_DEFAULT_ADMIN_PASSWORD)
ADMIN_FLAG = os.environ.get("CF_ADMIN_FLAG", "SBOB{admin_only_memo_flag}")

# 운영 배포인데 .env 설정이 빠져 기본값(개발용)이 그대로 쓰이면 세션/CSRF 위조나 관리자
# 계정 탈취로 이어질 수 있으므로, 그런 상태로는 앱이 아예 뜨지 않도록 막는다.
if IS_PRODUCTION:
    if SECRET_KEY == _DEV_DEFAULT_SECRET_KEY:
        raise RuntimeError(
            "CF_ENV=production 인데 CF_SECRET_KEY가 설정되지 않았습니다. .env에 무작위 값을 설정하세요."
        )
    if ADMIN_PASSWORD == _DEV_DEFAULT_ADMIN_PASSWORD:
        raise RuntimeError(
            "CF_ENV=production 인데 CF_ADMIN_PASSWORD가 기본값입니다. .env에서 변경하세요."
        )

app = Flask(__name__)
app.secret_key = SECRET_KEY

# 배포 구조상 앱 컨테이너는 Caddy(리버스 프록시)를 통해서만 접근 가능하다(docker-compose에서
# app 서비스는 포트를 직접 노출하지 않음). 따라서 Caddy가 앞단에서 붙여주는
# X-Forwarded-For/Proto 헤더를 1홉만 신뢰해도 안전하며, 이를 신뢰해야 클라이언트 실제 IP 기준
# 레이트리밋/보안 로그가 올바르게 동작하고 url_for가 https 스킴을 올바르게 인식한다.
if IS_PRODUCTION:
    from werkzeug.middleware.proxy_fix import ProxyFix

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0, x_port=0, x_prefix=0)

# 세션 만료/쿠키 보안 옵션: 로그인 유지 시간을 제한하고 클라이언트 스크립트/HTTP 평문 전송으로부터 세션 쿠키를 보호한다.
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=60),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    # 대용량 요청으로 인한 리소스 소모(DoS)를 막기 위해 요청 본문 크기를 제한한다.
    MAX_CONTENT_LENGTH=256 * 1024,
)

# CSRF 방어: 상태를 변경하는 모든 POST 폼에 hidden csrf_token 값을 강제한다.
csrf = CSRFProtect(app)

# 로그인/회원가입 등 인증 관련 엔드포인트에 대한 무차별 대입 공격을 완화한다.
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri="memory://",
    default_limits=["200 per minute"],
)


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
    db_existed = DB_PATH.exists()
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
                updated_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """
        )
        db.commit()

        # /api/notes가 요구하는 updated_at 컬럼을 이미 배포되어 있던(운영 DB 포함) memos
        # 테이블에도 안전하게 추가하는 마이그레이션. 이미 있으면 아무 것도 하지 않는다.
        memo_columns = {row[1] for row in db.execute("PRAGMA table_info(memos)").fetchall()}
        if "updated_at" not in memo_columns:
            db.execute("ALTER TABLE memos ADD COLUMN updated_at TIMESTAMP")
            db.execute("UPDATE memos SET updated_at = created_at WHERE updated_at IS NULL")
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

    if not db_existed and os.name == "posix":
        # SQLite 파일에는 비밀번호 해시가 들어있으므로 소유자만 읽고 쓸 수 있도록 권한을 제한한다.
        os.chmod(DB_PATH, stat.S_IRUSR | stat.S_IWUSR)


PASSWORD_MIN_LENGTH = 10


def validate_password_strength(password):
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"비밀번호는 최소 {PASSWORD_MIN_LENGTH}자 이상이어야 합니다."
    has_letter = any(c.isalpha() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    if sum([has_letter, has_digit, has_symbol]) < 2:
        return "비밀번호는 영문/숫자/특수문자 중 2종류 이상을 조합해야 합니다."
    return None


# IP 기준 레이트리밋(Flask-Limiter)만으로는 여러 IP를 돌려가며 특정 계정(특히 admin)만
# 노리는 분산 무차별 대입 공격을 막기 어려우므로, 계정(아이디) 기준으로도 잠금을 건다.
LOGIN_LOCKOUT_THRESHOLD = 5
LOGIN_LOCKOUT_WINDOW_SECONDS = 300
_failed_login_attempts = defaultdict(list)


def _record_failed_login(username):
    now = time.time()
    attempts = [t for t in _failed_login_attempts[username] if now - t < LOGIN_LOCKOUT_WINDOW_SECONDS]
    attempts.append(now)
    _failed_login_attempts[username] = attempts


def _is_login_locked(username):
    now = time.time()
    attempts = [t for t in _failed_login_attempts.get(username, []) if now - t < LOGIN_LOCKOUT_WINDOW_SECONDS]
    _failed_login_attempts[username] = attempts
    return len(attempts) >= LOGIN_LOCKOUT_THRESHOLD


def _clear_failed_logins(username):
    _failed_login_attempts.pop(username, None)


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
            return _error_page("권한이 없습니다", "이 페이지에 접근할 권한이 없습니다.", 403)
        return view(*args, **kwargs)

    return wrapped


def api_login_required(view):
    # HTML 라우트의 login_required와 달리, 로그인 페이지로 리다이렉트하지 않고
    # JSON 401을 반환한다 (API 스펙: "401 with a JSON body — not HTML, not a redirect").
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "authentication required"}), 401
        return view(*args, **kwargs)

    return wrapped


@app.before_request
def _assign_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)


@app.context_processor
def _inject_csp_nonce():
    return {"csp_nonce": g.get("csp_nonce", ""), "build_info": BUILD_INFO}


@app.after_request
def _set_security_headers(response):
    # 인라인 스크립트/스타일은 nonce가 있는 것만 허용하고, 그 외 외부 출처는 모두 차단한다(XSS 피해 최소화).
    nonce = g.get("csp_nonce", "")
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


BASE_TEMPLATE = """
<!doctype html>
<html>
<head>
<title>{{ title }}</title>
<style nonce="{{ csp_nonce }}">
  :root {
    --accent: #4f46e5;
    --accent-dark: #4338ca;
    --bg: #f3f4f8;
    --card-bg: #ffffff;
    --text: #1f2330;
    --muted: #6b7280;
    --border: #e5e7eb;
    --error: #dc2626;
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg); color: var(--text); margin: 0; min-height: 100vh;
  }
  nav {
    display: flex; align-items: center; gap: 6px; flex-wrap: wrap;
    padding: 14px 20px; background: var(--card-bg); border-bottom: 1px solid var(--border);
  }
  nav .brand { font-weight: 700; color: var(--accent); margin-right: auto; }
  nav .who { color: var(--muted); font-size: 13px; margin-right: 8px; }
  nav a { color: var(--text); text-decoration: none; font-size: 14px; padding: 6px 10px; border-radius: 6px; }
  nav a:hover { background: var(--bg); }
  .page { max-width: 480px; margin: 0 auto; padding: 32px 16px 60px; }
  .card {
    background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px;
    padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);
  }
  h1 { font-size: 19px; margin: 0 0 16px; }
  input[type=text], input[type=password], textarea {
    display: block; width: 100%; margin: 6px 0 14px; padding: 10px 12px;
    border: 1px solid var(--border); border-radius: 8px; font: inherit; background: #fafafa;
  }
  input[type=text]:focus, input[type=password]:focus, textarea:focus {
    outline: none; border-color: var(--accent); background: #fff;
  }
  input[type=submit] {
    width: auto; padding: 9px 18px; border: none; border-radius: 8px;
    background: var(--accent); color: #fff; font-weight: 600; font-size: 14px; cursor: pointer;
  }
  input[type=submit]:hover { background: var(--accent-dark); }
  .error {
    color: var(--error); background: #fef2f2; border: 1px solid #fecaca;
    padding: 10px 12px; border-radius: 8px; font-size: 14px; margin-bottom: 16px;
  }
  .btn {
    display: inline-block; padding: 8px 14px; border-radius: 8px; background: var(--accent);
    color: #fff !important; text-decoration: none; font-weight: 600; font-size: 14px;
  }
  .btn:hover { background: var(--accent-dark); }
  .memo-list { list-style: none; padding: 0; margin: 16px 0 0; display: flex; flex-direction: column; gap: 8px; }
  .memo-list li { border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; }
  .memo-list a { color: var(--text); text-decoration: none; font-weight: 600; }
  .memo-list small { color: var(--muted); display: block; margin-top: 2px; font-weight: 400; }
  table { border-collapse: collapse; width: 100%; }
  td, th { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border); }
  .inline { display: inline; }
  .muted { color: var(--muted); font-size: 13px; }
  #build-info { position: fixed; right: 6px; bottom: 4px; font-size: 11px; color: #b7bac2; }
</style>
</head>
<body>
<nav>
<span class="brand">CF 메모</span>
{% if session.get('username') %}
    <span class="who">{{ session['username'] }}님</span>
    <a href="{{ url_for('memo_list') }}">메모</a>
    {% if session.get('is_admin') %}
    <a href="{{ url_for('admin_users') }}">관리자</a>
    {% endif %}
    <a href="{{ url_for('logout') }}">로그아웃</a>
{% else %}
    <a href="{{ url_for('login') }}">로그인</a>
    <a href="{{ url_for('signup') }}">회원가입</a>
{% endif %}
</nav>
<div class="page">
{% if error %}
    <p class="error">{{ error }}</p>
{% endif %}
<div class="card">
{{ body|safe }}
</div>
</div>
<div id="build-info">build: {{ build_info }}</div>
<script nonce="{{ csp_nonce }}">
// 인라인 이벤트 핸들러(onclick=...) 대신 CSP를 통과하는 위임 방식으로 삭제 확인창을 띄운다.
document.addEventListener("submit", function (event) {
    if (event.target.matches(".confirm-delete")) {
        if (!confirm("삭제하시겠습니까?")) {
            event.preventDefault();
        }
    }
});
</script>
</body>
</html>
"""


def csrf_field():
    return f'<input type="hidden" name="csrf_token" value="{escape(generate_csrf())}">'


def _error_page(title, message, status):
    body = f"<h1>{escape(title)}</h1><p>{escape(message)}</p>"
    return render_template_string(BASE_TEMPLATE, title=title, body=body, error=None), status


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    # 토큰 위조/누락(공격 시도이거나 세션 만료)을 구분 없이 한 곳에서 기록해 모의 공방전 중
    # 이상 트래픽을 추적할 수 있게 한다.
    security_logger.warning(
        "CSRF validation failed from %s: %s", get_remote_address(), e.description
    )
    return _error_page("요청을 처리할 수 없습니다", "세션이 만료되었거나 위조된 요청입니다. 새로고침 후 다시 시도해주세요.", 400)


@app.errorhandler(429)
def handle_rate_limit(e):
    security_logger.warning("rate limit exceeded from %s", get_remote_address())
    return _error_page("요청이 너무 많습니다", "잠시 후 다시 시도해주세요.", 429)


@app.errorhandler(404)
def handle_not_found(e):
    return _error_page("페이지를 찾을 수 없습니다", "주소를 다시 확인해주세요.", 404)


@app.errorhandler(500)
def handle_internal_error(e):
    # 예외 상세(스택 트레이스 등)는 절대 클라이언트로 내려주지 않고 서버 로그에만 남긴다.
    security_logger.exception("unhandled server error")
    return _error_page("일시적인 오류가 발생했습니다", "잠시 후 다시 시도해주세요.", 500)


@app.route("/")
def index():
    # 로그인/회원가입 화면을 앱의 진짜 입구로 삼는다: 로그인 전에는 항상 로그인 화면부터
    # 보여주고, 로그인 후에는 바로 메모 목록으로 들어가게 한다.
    if "user_id" in session:
        return redirect(url_for("memo_list"))
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def signup():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            error = "아이디와 비밀번호를 모두 입력해주세요."
        else:
            error = validate_password_strength(password)

        if error is None:
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
                security_logger.info("new user signup: %s", username)
                return redirect(url_for("login"))

    body = """
    <h1>회원가입</h1>
    <form method="post">
        {csrf}
        아이디: <input type="text" name="username"><br>
        비밀번호: <input type="password" name="password"><br>
        <input type="submit" value="가입하기">
    </form>
    <p class="muted">이미 계정이 있으신가요? <a href="{login_url}">로그인</a></p>
    """.format(csrf=csrf_field(), login_url=url_for("login"))
    return render_template_string(BASE_TEMPLATE, title="회원가입", body=body, error=error)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username and _is_login_locked(username):
            error = "로그인 시도가 너무 많습니다. 5분 후 다시 시도해주세요."
            security_logger.warning(
                "login blocked (lockout) for %r from %s", username, get_remote_address()
            )
        else:
            db = get_db()
            user = db.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

            if user is None or not check_password_hash(user["password_hash"], password):
                error = "아이디 또는 비밀번호가 올바르지 않습니다."
                if username:
                    _record_failed_login(username)
                security_logger.warning(
                    "failed login attempt for %r from %s", username, get_remote_address()
                )
            else:
                _clear_failed_logins(username)
                session.clear()  # 세션 고정(session fixation) 공격 방지: 로그인 전 상태를 모두 폐기
                session.permanent = True  # PERMANENT_SESSION_LIFETIME 만료 정책 적용 (SEC-002)
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["is_admin"] = bool(user["is_admin"])
                security_logger.info("login: %s", username)
                return redirect(url_for("memo_new"))

    body = """
    <h1>로그인</h1>
    <form method="post">
        {csrf}
        아이디: <input type="text" name="username"><br>
        비밀번호: <input type="password" name="password"><br>
        <input type="submit" value="로그인">
    </form>
    <p class="muted">계정이 없으신가요? <a href="{signup_url}">회원가입</a></p>
    """.format(csrf=csrf_field(), signup_url=url_for("signup"))
    return render_template_string(BASE_TEMPLATE, title="로그인", body=body, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/memos")
@login_required
def memo_list():
    db = get_db()
    memos = db.execute(
        "SELECT id, title, created_at FROM memos WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],),
    ).fetchall()
    items = "".join(
        '<li><a href="{}">{}</a><small>{}</small></li>'.format(
            url_for("memo_detail", memo_id=m["id"]), escape(m["title"]), m["created_at"]
        )
        for m in memos
    ) or '<li class="muted">메모가 없습니다.</li>'
    body = """
    <h1>내 메모</h1>
    <p><a class="btn" href="{new_url}">+ 새 메모 작성</a></p>
    <ul class="memo-list">{items}</ul>
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
        {csrf}
        제목: <input type="text" name="title" value="{title}"><br>
        내용: <textarea name="content" rows="6">{content}</textarea><br>
        <input type="submit" value="저장">
    </form>
    """.format(
        csrf=csrf_field(),
        title=escape(request.form.get("title", "")),
        content=escape(request.form.get("content", "")),
    )
    return render_template_string(BASE_TEMPLATE, title="새 메모", body=body, error=error)


def _get_own_memo(memo_id):
    db = get_db()
    memo = db.execute("SELECT * FROM memos WHERE id = ?", (memo_id,)).fetchone()
    if memo is None:
        return None
    if memo["user_id"] != session["user_id"]:
        # 응답은 "존재하지 않음"과 동일한 404로 통일하되(IDOR로 존재 여부가 노출되지 않도록),
        # 서버 로그에는 실제로 남의 데이터에 접근을 시도한 이벤트만 구분해서 남긴다.
        # id가 낮을수록(특히 1번, 관리자 flag) 가장 먼저 시도될 만한 값이라 탐지 가치가 크다.
        security_logger.warning(
            "IDOR attempt: user=%s tried memo_id=%s (owned by user_id=%s) from %s",
            session.get("username"), memo_id, memo["user_id"], get_remote_address(),
        )
        return None
    return memo


@app.route("/memos/<int:memo_id>")
@login_required
def memo_detail(memo_id):
    memo = _get_own_memo(memo_id)
    if memo is None:
        return _error_page("메모를 찾을 수 없습니다", "요청하신 메모가 없거나 접근 권한이 없습니다.", 404)

    body = """
    <h1>{title}</h1>
    <pre>{content}</pre>
    <p>
        <a href="{edit_url}">수정</a>
        <form method="post" action="{delete_url}" class="inline confirm-delete">
            {csrf}
            <input type="submit" value="삭제">
        </form>
    </p>
    <p><a href="{list_url}">목록으로</a></p>
    """.format(
        title=escape(memo["title"]),
        content=escape(memo["content"]),
        edit_url=url_for("memo_edit", memo_id=memo["id"]),
        delete_url=url_for("memo_delete", memo_id=memo["id"]),
        list_url=url_for("memo_list"),
        csrf=csrf_field(),
    )
    return render_template_string(BASE_TEMPLATE, title=memo["title"], body=body, error=None)


@app.route("/memos/<int:memo_id>/edit", methods=["GET", "POST"])
@login_required
def memo_edit(memo_id):
    memo = _get_own_memo(memo_id)
    if memo is None:
        return _error_page("메모를 찾을 수 없습니다", "요청하신 메모가 없거나 접근 권한이 없습니다.", 404)

    error = None
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        if not title or not content:
            error = "제목과 내용을 모두 입력해주세요."
        else:
            db = get_db()
            db.execute(
                "UPDATE memos SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?",
                (title, content, memo_id, session["user_id"]),
            )
            db.commit()
            return redirect(url_for("memo_detail", memo_id=memo_id))

    body = """
    <h1>메모 수정</h1>
    <form method="post">
        {csrf}
        제목: <input type="text" name="title" value="{title}"><br>
        내용: <textarea name="content" rows="6">{content}</textarea><br>
        <input type="submit" value="수정">
    </form>
    """.format(
        csrf=csrf_field(),
        title=escape(request.form.get("title", memo["title"])),
        content=escape(request.form.get("content", memo["content"])),
    )
    return render_template_string(BASE_TEMPLATE, title="메모 수정", body=body, error=error)


@app.route("/memos/<int:memo_id>/delete", methods=["POST"])
@login_required
def memo_delete(memo_id):
    memo = _get_own_memo(memo_id)
    if memo is None:
        return _error_page("메모를 찾을 수 없습니다", "요청하신 메모가 없거나 접근 권한이 없습니다.", 404)

    db = get_db()
    db.execute(
        "DELETE FROM memos WHERE id = ? AND user_id = ?", (memo_id, session["user_id"])
    )
    db.commit()
    return redirect(url_for("memo_list"))


def _serialize_note(memo):
    updated_at = memo["updated_at"] if memo["updated_at"] is not None else memo["created_at"]
    return {
        "id": memo["id"],
        "title": memo["title"],
        "body": memo["content"],
        "created_at": str(memo["created_at"]),
        "updated_at": str(updated_at),
    }


@app.route("/api/notes", methods=["GET"])
@api_login_required
def api_notes_list():
    db = get_db()
    rows = db.execute(
        "SELECT id, title, content, created_at, updated_at FROM memos WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],),
    ).fetchall()
    return jsonify({"notes": [_serialize_note(r) for r in rows]})


@app.route("/api/notes", methods=["POST"])
@csrf.exempt  # JSON 전용 엔드포인트: 아래 request.is_json 검사 + CORS 미허용으로 CSRF를 방어한다.
@api_login_required
@limiter.limit("30 per minute")
def api_notes_create():
    # 브라우저가 cross-site fetch에 커스텀 Content-Type(application/json)을 실어 보내려면
    # CORS preflight를 통과해야 하는데, 이 서버는 CORS 헤더를 전혀 내려주지 않으므로 다른
    # 오리진에서의 요청은 프리플라이트 단계에서 막힌다. 즉 form 기반 CSRF는 애초에 불가능하다.
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "invalid JSON body"}), 400

    title = data.get("title")
    title = title.strip() if isinstance(title, str) else ""
    if not title:
        return jsonify({"error": "title is required"}), 400

    body = data.get("body", "")
    if not isinstance(body, str):
        body = ""

    db = get_db()
    cur = db.execute(
        "INSERT INTO memos (user_id, title, content, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
        (session["user_id"], title, body),
    )
    db.commit()
    row = db.execute(
        "SELECT id, title, content, created_at, updated_at FROM memos WHERE id = ?",
        (cur.lastrowid,),
    ).fetchone()
    security_logger.info("api note created: user=%s note_id=%s", session.get("username"), row["id"])
    return jsonify(_serialize_note(row)), 201


@app.route("/api/notes/<int:note_id>", methods=["GET"])
@api_login_required
def api_notes_detail(note_id):
    memo = _get_own_memo(note_id)
    if memo is None:
        # 존재하지 않는 note와 남의 note를 구분하지 않고 둘 다 404로 응답한다(IDOR로 인한
        # 존재 여부 노출 방지 — 스펙에도 403이 아닌 404로 명시되어 있음).
        return jsonify({"error": "note not found"}), 404
    return jsonify(_serialize_note(memo))


@app.route("/admin")
@admin_required
def admin_users():
    security_logger.info("admin panel access: %s", session.get("username"))
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
    # host="0.0.0.0": 컨테이너 밖(포트 매핑)에서 접속하려면 필요하다.
    # 운영 환경(CF_ENV=production)에서는 Werkzeug 디버거/리로더를 반드시 꺼야 한다.
    # 디버거가 켜진 채로 외부에 노출되면 임의 코드 실행으로 이어질 수 있다.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=not IS_PRODUCTION)

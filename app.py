# -*- coding: utf-8 -*-
"""IJARA TOP - PropTech marketplace MVP (Flask + SQLite)
Ishga tushirish:  pip install -r requirements.txt  &&  python app.py
Admin: /admin/kirish  (ADMIN_USER / ADMIN_PASS env yoki birinchi ishga tushishda konsolga chiqadi)"""
import os, json, sqlite3, secrets, time, uuid
from functools import wraps
from flask import (Flask, g, request, session, redirect, url_for, flash, abort,
                   render_template, send_from_directory)
from werkzeug.security import generate_password_hash, check_password_hash
from jinja2 import DictLoader

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "ijara.db")
UP = os.path.join(BASE, "uploads")
os.makedirs(UP, exist_ok=True)

app = Flask(__name__)
kf = os.path.join(BASE, ".secret_key")
if not os.path.exists(kf):
    open(kf, "w").write(secrets.token_hex(32))
app.secret_key = open(kf).read().strip()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("HTTPS") == "1",
                  MAX_CONTENT_LENGTH=5 * 1024 * 1024, PERMANENT_SESSION_LIFETIME=3600 * 8)

REGIONS = ["Yunusobod", "Chilonzor", "Mirzo Ulug'bek", "Yakkasaroy", "Shayxontohur",
           "Sergeli", "Olmazor", "Mirobod", "Yashnobod", "Uchtepa", "Bektemir", "Yangihayot"]

# ---------------------------------------------------------------- DB
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

def init_db():
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, pw TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, username TEXT UNIQUE, pw TEXT);
    CREATE TABLE IF NOT EXISTS listings(id INTEGER PRIMARY KEY, user_id INT, title TEXT, descr TEXT, region TEXT,
        price INT, rooms INT, phone TEXT, photo TEXT, status TEXT DEFAULT 'pending', created TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS edits(id INTEGER PRIMARY KEY, listing_id INT, data TEXT, photo TEXT, status TEXT DEFAULT 'pending');
    CREATE TABLE IF NOT EXISTS favs(user_id INT, listing_id INT, PRIMARY KEY(user_id, listing_id));
    """)
    if not c.execute("SELECT 1 FROM admins").fetchone():
        u = os.environ.get("ADMIN_USER", "admin")
        p = os.environ.get("ADMIN_PASS") or secrets.token_urlsafe(10)
        c.execute("INSERT INTO admins(username,pw) VALUES(?,?)", (u, generate_password_hash(p)))
        print(f"\n=== ADMIN yaratildi ===\n login: {u}\n parol: {p}\n (saqlab qo'ying!)\n")
    c.commit(); c.close()

# ---------------------------------------------------------------- Xavfsizlik
def csrf():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]
app.jinja_env.globals["csrf"] = csrf

@app.before_request
def check_csrf():
    if request.method == "POST":
        t = request.form.get("_csrf", "")
        if not t or not secrets.compare_digest(t, session.get("_csrf", "")):
            abort(400)

@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "same-origin"
    r.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'"
    return r

ATT = {}
def blocked(key):
    now = time.time()
    ATT[key] = [t for t in ATT.get(key, []) if now - t < 300]
    return len(ATT[key]) >= 5
def fail(key): ATT.setdefault(key, []).append(time.time())

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "uid" not in session:
            flash("Avval tizimga kiring", "err"); return redirect(url_for("login"))
        return f(*a, **k)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a, **k):
        if "aid" not in session: return redirect(url_for("admin_login"))
        return f(*a, **k)
    return w

def save_photo(f):
    if not f or not f.filename: return None
    h = f.read(12); f.seek(0)
    ext = ("jpg" if h[:3] == b"\xff\xd8\xff" else "png" if h[:4] == b"\x89PNG"
           else "webp" if h[:4] == b"RIFF" and h[8:12] == b"WEBP" else None)
    if not ext: raise ValueError("Faqat JPG, PNG yoki WEBP rasm yuklang")
    name = f"{uuid.uuid4().hex}.{ext}"
    f.save(os.path.join(UP, name)); return name

def form_data():
    f = request.form
    t, d, r, ph = f.get("title", "").strip(), f.get("descr", "").strip(), f.get("region", ""), f.get("phone", "").strip()
    try: p, rm = int(f.get("price", "")), int(f.get("rooms", ""))
    except ValueError: raise ValueError("Narx va xonalar soni son bo'lishi kerak")
    if not (3 <= len(t) <= 100) or len(d) > 2000 or r not in REGIONS or not (0 < p < 10**9) or not (1 <= rm <= 20):
        raise ValueError("Ma'lumotlar noto'g'ri to'ldirilgan")
    if not (7 <= len(ph) <= 20) or not all(c in "+0123456789 -()" for c in ph):
        raise ValueError("Telefon raqami noto'g'ri")
    return dict(title=t, descr=d, region=r, price=p, rooms=rm, phone=ph)

# ---------------------------------------------------------------- Foydalanuvchi
@app.route("/")
def index():
    q, reg = request.args.get("q", "").strip(), request.args.get("region", "")
    mn, mx, rm = request.args.get("min", ""), request.args.get("max", ""), request.args.get("rooms", "")
    sql, a = "SELECT * FROM listings WHERE status='approved'", []
    if q: sql += " AND (title LIKE ? OR descr LIKE ?)"; a += [f"%{q}%"] * 2
    if reg in REGIONS: sql += " AND region=?"; a.append(reg)
    if mn.isdigit(): sql += " AND price>=?"; a.append(int(mn))
    if mx.isdigit(): sql += " AND price<=?"; a.append(int(mx))
    if rm.isdigit(): sql += " AND rooms=?"; a.append(int(rm))
    sort = {"arzon": "price ASC", "qimmat": "price DESC"}.get(request.args.get("s"), "id DESC")
    rows = db().execute(sql + " ORDER BY " + sort, a).fetchall()
    favs = set()
    if "uid" in session:
        favs = {r[0] for r in db().execute("SELECT listing_id FROM favs WHERE user_id=?", (session["uid"],))}
    return render_template("index.html", rows=rows, favs=favs, regions=REGIONS, a=request.args)

@app.route("/uy/<int:i>")
def detail(i):
    l = db().execute("SELECT l.*, u.username FROM listings l JOIN users u ON u.id=l.user_id WHERE l.id=?", (i,)).fetchone()
    if not l: abort(404)
    if l["status"] != "approved" and session.get("uid") != l["user_id"] and "aid" not in session: abort(404)
    return render_template("detail.html", l=l)

@app.route("/media/<name>")
def media(name): return send_from_directory(UP, name)

@app.route("/royxat", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u, p = request.form.get("username", "").strip(), request.form.get("password", "")
        if not (3 <= len(u) <= 30) or not u.replace("_", "").isalnum():
            flash("Login 3-30 belgi: harf, raqam yoki _", "err")
        elif len(p) < 8 or p.isdigit() or p.isalpha():
            flash("Parol kamida 8 belgi, harf va raqam aralash bo'lsin", "err")
        else:
            try:
                db().execute("INSERT INTO users(username,pw) VALUES(?,?)", (u, generate_password_hash(p)))
                db().commit(); flash("Ro'yxatdan o'tdingiz! Endi kiring", "ok"); return redirect(url_for("login"))
            except sqlite3.IntegrityError: flash("Bu login band", "err")
    return render_template("auth.html", title="Ro'yxatdan o'tish", btn="Ro'yxatdan o'tish")

@app.route("/kirish", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        k = "u" + request.remote_addr
        if blocked(k): flash("Juda ko'p urinish. 5 daqiqadan so'ng qayta urining", "err")
        else:
            u = db().execute("SELECT * FROM users WHERE username=?", (request.form.get("username", "").strip(),)).fetchone()
            if u and check_password_hash(u["pw"], request.form.get("password", "")):
                session.clear(); session.permanent = True
                session["uid"], session["uname"] = u["id"], u["username"]
                return redirect(url_for("index"))
            fail(k); flash("Login yoki parol noto'g'ri", "err")
    return render_template("auth.html", title="Kirish", btn="Kirish")

@app.route("/chiqish", methods=["POST"])
def logout():
    session.clear(); return redirect(url_for("index"))

@app.route("/qoshish", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        try:
            d = form_data(); d["photo"] = save_photo(request.files.get("photo"))
            db().execute("INSERT INTO listings(user_id,title,descr,region,price,rooms,phone,photo) VALUES(?,?,?,?,?,?,?,?)",
                         (session["uid"], d["title"], d["descr"], d["region"], d["price"], d["rooms"], d["phone"], d["photo"]))
            db().commit(); flash("E'lon yuborildi! Admin tasdiqlagach saytda ko'rinadi ✅", "ok")
            return redirect(url_for("mine"))
        except ValueError as e: flash(str(e), "err")
    return render_template("form.html", l=request.form, regions=REGIONS, title="Yangi e'lon")

@app.route("/mening")
@login_required
def mine():
    rows = db().execute("SELECT l.*, (SELECT COUNT(*) FROM edits e WHERE e.listing_id=l.id AND e.status='pending') AS pe "
                        "FROM listings l WHERE user_id=? ORDER BY id DESC", (session["uid"],)).fetchall()
    return render_template("mine.html", rows=rows)

@app.route("/tahrir/<int:i>", methods=["GET", "POST"])
@login_required
def edit(i):
    l = db().execute("SELECT * FROM listings WHERE id=? AND user_id=?", (i, session["uid"])).fetchone()
    if not l: abort(404)
    if request.method == "POST":
        try:
            d = form_data(); ph = save_photo(request.files.get("photo"))
            db().execute("DELETE FROM edits WHERE listing_id=? AND status='pending'", (i,))
            db().execute("INSERT INTO edits(listing_id,data,photo) VALUES(?,?,?)", (i, json.dumps(d), ph))
            db().commit(); flash("O'zgarish admin tasdig'iga yuborildi ✅", "ok"); return redirect(url_for("mine"))
        except ValueError as e: flash(str(e), "err")
    return render_template("form.html", l=l, regions=REGIONS, title="E'lonni tahrirlash")

@app.route("/saqlash/<int:i>", methods=["POST"])
@login_required
def fav(i):
    c = db()
    if c.execute("SELECT 1 FROM favs WHERE user_id=? AND listing_id=?", (session["uid"], i)).fetchone():
        c.execute("DELETE FROM favs WHERE user_id=? AND listing_id=?", (session["uid"], i))
    elif c.execute("SELECT 1 FROM listings WHERE id=? AND status='approved'", (i,)).fetchone():
        c.execute("INSERT INTO favs VALUES(?,?)", (session["uid"], i))
    c.commit(); return redirect(request.referrer or url_for("index"))

@app.route("/saqlanganlar")
@login_required
def saved():
    rows = db().execute("SELECT l.* FROM listings l JOIN favs f ON f.listing_id=l.id WHERE f.user_id=? AND l.status='approved'",
                        (session["uid"],)).fetchall()
    return render_template("index.html", rows=rows, favs={r["id"] for r in rows}, regions=REGIONS, a={}, saved=True)

# ---------------------------------------------------------------- Admin
@app.route("/admin/kirish", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        k = "a" + request.remote_addr
        if blocked(k): flash("Juda ko'p urinish. Keyinroq urining", "err")
        else:
            a = db().execute("SELECT * FROM admins WHERE username=?", (request.form.get("username", "").strip(),)).fetchone()
            if a and check_password_hash(a["pw"], request.form.get("password", "")):
                session.clear(); session.permanent = True; session["aid"] = a["id"]
                return redirect(url_for("admin"))
            fail(k); flash("Admin login yoki parol noto'g'ri", "err")
    return render_template("auth.html", title="🛡️ Admin kirish", btn="Admin panelga kirish", admin=True)

@app.route("/admin")
@admin_required
def admin():
    c = db()
    pend = c.execute("SELECT l.*, u.username FROM listings l JOIN users u ON u.id=l.user_id WHERE status='pending' ORDER BY id").fetchall()
    eds = c.execute("SELECT e.*, l.title AS old_title, l.price AS old_price, l.region AS old_region FROM edits e "
                    "JOIN listings l ON l.id=e.listing_id WHERE e.status='pending'").fetchall()
    eds = [dict(e, d=json.loads(e["data"])) for e in eds]
    st = dict(users=c.execute("SELECT COUNT(*) FROM users").fetchone()[0],
              live=c.execute("SELECT COUNT(*) FROM listings WHERE status='approved'").fetchone()[0],
              pend=len(pend), eds=len(eds))
    return render_template("admin.html", pend=pend, eds=eds, st=st)

@app.route("/admin/uy/<int:i>/<act>", methods=["POST"])
@admin_required
def admin_listing(i, act):
    if act not in ("approve", "reject"): abort(404)
    db().execute("UPDATE listings SET status=? WHERE id=?", ("approved" if act == "approve" else "rejected", i))
    db().commit(); flash("Bajarildi", "ok"); return redirect(url_for("admin"))

@app.route("/admin/tahrir/<int:i>/<act>", methods=["POST"])
@admin_required
def admin_edit(i, act):
    if act not in ("approve", "reject"): abort(404)
    e = db().execute("SELECT * FROM edits WHERE id=? AND status='pending'", (i,)).fetchone()
    if not e: abort(404)
    if act == "approve":
        d = json.loads(e["data"])
        db().execute("UPDATE listings SET title=?,descr=?,region=?,price=?,rooms=?,phone=?,photo=COALESCE(?,photo) WHERE id=?",
                     (d["title"], d["descr"], d["region"], d["price"], d["rooms"], d["phone"], e["photo"], e["listing_id"]))
    db().execute("UPDATE edits SET status=? WHERE id=?", ("approved" if act == "approve" else "rejected", i))
    db().commit(); flash("Bajarildi", "ok"); return redirect(url_for("admin"))

# ---------------------------------------------------------------- Dizayn (shablonlar)
CSS = """
:root{--a:#7c3aed;--b:#ec4899;--c:#f59e0b;--d:#06b6d4;--ink:#1e1b4b}
*{box-sizing:border-box}body{margin:0;font-family:'Segoe UI',system-ui,sans-serif;background:#f5f3ff;color:var(--ink)}
a{color:inherit;text-decoration:none}
nav{display:flex;gap:14px;align-items:center;padding:14px 5vw;background:linear-gradient(90deg,#4c1d95,#be185d);color:#fff;position:sticky;top:0;z-index:9;flex-wrap:wrap}
nav .logo{font-size:1.6rem;font-weight:900;margin-right:auto;letter-spacing:1px}nav .logo span{color:#fde047}
nav a,nav button{color:#fff;background:rgba(255,255,255,.15);border:0;padding:8px 14px;border-radius:99px;cursor:pointer;font-size:.9rem}
nav a:hover,nav button:hover{background:rgba(255,255,255,.3)}nav form{margin:0}
.hero{position:relative;overflow:hidden;padding:70px 5vw 110px;color:#fff;text-align:center;background:linear-gradient(135deg,#7c3aed,#ec4899 55%,#f59e0b)}
.hero h1{font-size:clamp(2rem,6vw,3.8rem);margin:0 0 10px;text-shadow:0 4px 20px rgba(0,0,0,.25)}.hero p{font-size:1.2rem;opacity:.95}
.hero .fl{position:absolute;font-size:4rem;opacity:.25;animation:fl 6s ease-in-out infinite}
@keyframes fl{50%{transform:translateY(-22px) rotate(8deg)}}
.box{max-width:1150px;margin:-60px auto 30px;padding:0 4vw;position:relative}
.filter{background:#fff;border-radius:22px;padding:18px;box-shadow:0 20px 50px rgba(124,58,237,.25);display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
input,select,textarea{width:100%;padding:11px 13px;border:2px solid #e9d5ff;border-radius:12px;font-size:.95rem;background:#faf5ff;font-family:inherit}
input:focus,select:focus,textarea:focus{outline:0;border-color:var(--a)}
.btn{display:inline-block;border:0;cursor:pointer;color:#fff;font-weight:700;padding:11px 20px;border-radius:12px;background:linear-gradient(90deg,var(--a),var(--b));font-size:.95rem;transition:.2s}
.btn:hover{transform:translateY(-2px);box-shadow:0 8px 20px rgba(236,72,153,.4)}.btn.g{background:linear-gradient(90deg,#10b981,#06b6d4)}.btn.r{background:linear-gradient(90deg,#ef4444,#f97316)}
.grid{max-width:1150px;margin:0 auto;padding:10px 4vw 50px;display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:22px}
.card{background:#fff;border-radius:20px;overflow:hidden;box-shadow:0 8px 24px rgba(76,29,149,.12);transition:.25s;position:relative}
.card:hover{transform:translateY(-8px);box-shadow:0 18px 40px rgba(236,72,153,.3)}
.ph{height:170px;background-size:cover;background-position:center;display:flex;align-items:center;justify-content:center;font-size:4rem}
.card .in{padding:14px}.card h3{margin:0 0 6px;font-size:1.05rem}.price{font-size:1.3rem;font-weight:900;color:var(--a)}
.tag{display:inline-block;padding:3px 10px;border-radius:99px;background:#ede9fe;font-size:.78rem;margin:3px 3px 0 0}
.heart{position:absolute;top:10px;right:10px;background:#fff;border:0;border-radius:50%;width:38px;height:38px;font-size:1.2rem;cursor:pointer;box-shadow:0 3px 10px rgba(0,0,0,.2)}
.wrap{max-width:560px;margin:40px auto;padding:30px;background:#fff;border-radius:24px;box-shadow:0 20px 50px rgba(124,58,237,.2)}
.wide{max-width:1000px}.wrap h2{margin-top:0}label{display:block;margin:12px 0 4px;font-weight:600}
.msg{max-width:1000px;margin:14px auto;padding:12px 18px;border-radius:14px;font-weight:600}.ok{background:#d1fae5;color:#065f46}.err{background:#fee2e2;color:#991b1b}
.st{padding:3px 10px;border-radius:99px;color:#fff;font-size:.78rem}.pending{background:#f59e0b}.approved{background:#10b981}.rejected{background:#ef4444}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:20px}
.stats div{padding:18px;border-radius:18px;color:#fff;font-size:2rem;font-weight:900;text-align:center}.stats small{display:block;font-size:.8rem;font-weight:400}
.row{display:flex;gap:14px;align-items:center;padding:12px;border-bottom:1px solid #ede9fe;flex-wrap:wrap}.row .t{flex:1;min-width:200px}
.dp{height:340px;border-radius:20px;background-size:cover;background-position:center;display:flex;align-items:center;justify-content:center;font-size:8rem}
footer{text-align:center;padding:30px;color:#6b21a8}
"""
GR = ["#a78bfa,#ec4899", "#fbbf24,#f43f5e", "#22d3ee,#6366f1", "#34d399,#06b6d4", "#fb923c,#e11d48", "#c084fc,#38bdf8"]

T = {}
T["base.html"] = """<!doctype html><html lang="uz"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ijara Top — uy-joy ijarasi</title><style>""" + CSS + """</style></head><body>
<nav><a class="logo" href="/">🏠 IJARA<span>TOP</span></a>
{% if session.aid %}<a href="/admin">🛡️ Admin panel</a><form method="post" action="/chiqish"><input type="hidden" name="_csrf" value="{{csrf()}}"><button>Chiqish</button></form>
{% elif session.uid %}<a href="/qoshish">➕ E'lon qo'shish</a><a href="/mening">📋 E'lonlarim</a><a href="/saqlanganlar">❤️ Saqlangan</a>
<form method="post" action="/chiqish"><input type="hidden" name="_csrf" value="{{csrf()}}"><button>{{session.uname}} · Chiqish</button></form>
{% else %}<a href="/kirish">Kirish</a><a href="/royxat">Ro'yxatdan o'tish</a>{% endif %}</nav>
{% for c,m in get_flashed_messages(with_categories=true) %}<div class="msg {{c}}">{{m}}</div>{% endfor %}
{% block body %}{% endblock %}<footer>© 2026 IJARA TOP · Ishonchli, tekshirilgan e'lonlar 🔒</footer></body></html>"""

T["_card.html"] = """<div class="card"><a href="/uy/{{l.id}}"><div class="ph" style="{% if l.photo %}background-image:url('/media/{{l.photo}}'){% else %}background:linear-gradient(135deg,{{grads[l.id%6]}}){% endif %}">{% if not l.photo %}🏡{% endif %}</div></a>
<form method="post" action="/saqlash/{{l.id}}">{% if session.uid %}<input type="hidden" name="_csrf" value="{{csrf()}}"><button class="heart">{{'❤️' if l.id in favs else '🤍'}}</button>{% endif %}</form>
<div class="in"><h3>{{l.title}}</h3><div class="price">{{'{:,}'.format(l.price).replace(',',' ')}} so'm<small>/oy</small></div>
<span class="tag">📍 {{l.region}}</span><span class="tag">🛏️ {{l.rooms}} xona</span></div></div>"""

T["index.html"] = """{% extends 'base.html' %}{% block body %}
{% if not saved %}<div class="hero"><span class="fl" style="left:6%;top:20%">🏠</span><span class="fl" style="right:8%;top:15%;animation-delay:1s">🔑</span><span class="fl" style="left:25%;bottom:10%;animation-delay:2s">🏢</span><span class="fl" style="right:22%;bottom:12%;animation-delay:3s">🛋️</span>
<h1>Orzuingdagi uyni top! ✨</h1><p>Toshkent bo'yicha tekshirilgan ijara e'lonlari — tez, qulay, xavfsiz</p></div>
<div class="box"><form class="filter" method="get"><input name="q" placeholder="🔎 Qidirish..." value="{{a.get('q','')}}">
<select name="region"><option value="">Barcha hudud</option>{% for r in regions %}<option {{'selected' if a.get('region')==r}}>{{r}}</option>{% endfor %}</select>
<input name="min" type="number" placeholder="Narx dan" value="{{a.get('min','')}}"><input name="max" type="number" placeholder="Narx gacha" value="{{a.get('max','')}}">
<select name="rooms"><option value="">Xonalar</option>{% for n in range(1,6) %}<option value="{{n}}" {{'selected' if a.get('rooms')==n|string}}>{{n}} xona</option>{% endfor %}</select>
<select name="s"><option value="">Yangilari</option><option value="arzon" {{'selected' if a.get('s')=='arzon'}}>Arzonroq</option><option value="qimmat" {{'selected' if a.get('s')=='qimmat'}}>Qimmatroq</option></select>
<button class="btn">Topish</button></form></div>{% else %}<h2 style="text-align:center;margin-top:30px">❤️ Saqlangan uylar</h2>{% endif %}
<div class="grid">{% for l in rows %}{% include '_card.html' %}{% else %}<p style="grid-column:1/-1;text-align:center;font-size:1.2rem">😕 Hozircha e'lon topilmadi</p>{% endfor %}</div>{% endblock %}"""

T["detail.html"] = """{% extends 'base.html' %}{% block body %}<div class="wrap wide">
<div class="dp" style="{% if l.photo %}background-image:url('/media/{{l.photo}}'){% else %}background:linear-gradient(135deg,{{grads[l.id%6]}}){% endif %}">{% if not l.photo %}🏡{% endif %}</div>
<h2 style="margin-top:18px">{{l.title}} {% if l.status!='approved' %}<span class="st {{l.status}}">{{l.status}}</span>{% endif %}</h2>
<div class="price" style="font-size:2rem">{{'{:,}'.format(l.price).replace(',',' ')}} so'm / oy</div>
<p><span class="tag">📍 {{l.region}}</span><span class="tag">🛏️ {{l.rooms}} xona</span><span class="tag">👤 {{l.username}}</span><span class="tag">📅 {{l.created[:10]}}</span></p>
<p style="white-space:pre-line;line-height:1.7">{{l.descr}}</p>
{% if session.uid or session.aid %}<a class="btn g" href="tel:{{l.phone}}">📞 {{l.phone}}</a>{% else %}<a class="btn" href="/kirish">🔒 Aloqa uchun tizimga kiring</a>{% endif %}</div>{% endblock %}"""

T["auth.html"] = """{% extends 'base.html' %}{% block body %}<div class="wrap"><h2>{{title}}</h2><form method="post" autocomplete="off">
<input type="hidden" name="_csrf" value="{{csrf()}}"><label>Login</label><input name="username" required maxlength="30">
<label>Parol</label><input name="password" type="password" required maxlength="100">
{% if not admin and title.startswith('Ro') %}<small>Kamida 8 belgi, harf va raqam aralash</small>{% endif %}<br><br><button class="btn" style="width:100%">{{btn}}</button></form></div>{% endblock %}"""

T["form.html"] = """{% extends 'base.html' %}{% block body %}<div class="wrap"><h2>{{title}}</h2>
{% if l.id is defined %}<small>⚠️ O'zgarishlar admin tasdiqlagach kuchga kiradi</small>{% endif %}
<form method="post" enctype="multipart/form-data"><input type="hidden" name="_csrf" value="{{csrf()}}">
<label>Sarlavha</label><input name="title" required maxlength="100" value="{{l.title or ''}}">
<label>Hudud</label><select name="region">{% for r in regions %}<option {{'selected' if l.region==r}}>{{r}}</option>{% endfor %}</select>
<label>Narx (so'm/oy)</label><input name="price" type="number" required value="{{l.price or ''}}">
<label>Xonalar soni</label><input name="rooms" type="number" min="1" max="20" required value="{{l.rooms or ''}}">
<label>Telefon</label><input name="phone" required placeholder="+998 90 123 45 67" value="{{l.phone or ''}}">
<label>Tavsif</label><textarea name="descr" rows="5" maxlength="2000">{{l.descr or ''}}</textarea>
<label>📷 Foto (JPG/PNG/WEBP, 5MB gacha)</label><input type="file" name="photo" accept="image/*"><br><br>
<button class="btn" style="width:100%">Yuborish</button></form></div>{% endblock %}"""

T["mine.html"] = """{% extends 'base.html' %}{% block body %}<div class="wrap wide"><h2>📋 Mening e'lonlarim</h2>
{% for l in rows %}<div class="row"><div class="t"><b>{{l.title}}</b><br>{{l.region}} · {{'{:,}'.format(l.price)}} so'm</div>
<span class="st {{l.status}}">{{l.status}}</span>{% if l.pe %}<span class="st pending">tahrir kutilmoqda</span>{% endif %}
<a class="btn" href="/tahrir/{{l.id}}">✏️ Tahrirlash</a></div>{% else %}<p>Hali e'lon yo'q. <a href="/qoshish"><u>Birinchisini qo'shing!</u></a></p>{% endfor %}</div>{% endblock %}"""

T["admin.html"] = """{% extends 'base.html' %}{% block body %}<div class="wrap wide"><h2>🛡️ Admin panel</h2>
<div class="stats"><div style="background:linear-gradient(135deg,#7c3aed,#ec4899)">{{st.users}}<small>Foydalanuvchilar</small></div>
<div style="background:linear-gradient(135deg,#10b981,#06b6d4)">{{st.live}}<small>Faol e'lonlar</small></div>
<div style="background:linear-gradient(135deg,#f59e0b,#ef4444)">{{st.pend}}<small>Yangi so'rovlar</small></div>
<div style="background:linear-gradient(135deg,#6366f1,#22d3ee)">{{st.eds}}<small>Tahrir so'rovlari</small></div></div>
<h3>🆕 Yangi e'lon so'rovlari</h3>
{% for l in pend %}<div class="row"><div class="t"><a href="/uy/{{l.id}}"><b>{{l.title}}</b></a><br>{{l.region}} · {{'{:,}'.format(l.price)}} so'm · 👤 {{l.username}}</div>
<form method="post" action="/admin/uy/{{l.id}}/approve"><input type="hidden" name="_csrf" value="{{csrf()}}"><button class="btn g">✅ Tasdiqlash</button></form>
<form method="post" action="/admin/uy/{{l.id}}/reject"><input type="hidden" name="_csrf" value="{{csrf()}}"><button class="btn r">❌ Rad etish</button></form></div>{% else %}<p>Yangi so'rov yo'q 🎉</p>{% endfor %}
<h3>✏️ Tahrir so'rovlari</h3>
{% for e in eds %}<div class="row"><div class="t"><b>{{e.old_title}}</b> → <b>{{e.d.title}}</b><br>{{e.old_region}} → {{e.d.region}} · {{'{:,}'.format(e.old_price)}} → {{'{:,}'.format(e.d.price)}} so'm{% if e.photo %} · 📷 yangi foto{% endif %}</div>
<form method="post" action="/admin/tahrir/{{e.id}}/approve"><input type="hidden" name="_csrf" value="{{csrf()}}"><button class="btn g">✅ Tasdiqlash</button></form>
<form method="post" action="/admin/tahrir/{{e.id}}/reject"><input type="hidden" name="_csrf" value="{{csrf()}}"><button class="btn r">❌ Rad etish</button></form></div>{% else %}<p>Tahrir so'rovi yo'q</p>{% endfor %}</div>{% endblock %}"""

app.jinja_loader = DictLoader(T)
app.jinja_env.globals["grads"] = GR

@app.errorhandler(400)
def e400(_): return "Xavfsizlik tekshiruvi muvaffaqiyatsiz (CSRF). Sahifani yangilang.", 400
@app.errorhandler(404)
def e404(_): return render_template("auth.html", title="404 — Sahifa topilmadi 😕", btn="Bosh sahifa") if False else ("Topilmadi 😕 <a href='/'>Bosh sahifa</a>", 404)
@app.errorhandler(413)
def e413(_): return "Fayl juda katta (5MB gacha)", 413

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)

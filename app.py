import os, secrets, sqlite3, time, threading
from contextlib import closing
from flask import Flask, render_template, request, session, redirect, url_for, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get('SECRET_KEY') or secrets.token_hex(32), SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=bool(os.environ.get('RENDER')), MAX_CONTENT_LENGTH=16384)
DB=os.environ.get('LAB_DB','lab.sqlite3')
auth_lock=threading.Lock()
auth_window=[]
def db():
    c=sqlite3.connect(DB,timeout=5); c.row_factory=sqlite3.Row; return c
with closing(db()) as c, c:
    c.executescript('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL); CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, owner INTEGER NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL);')
@app.before_request
def protect():
    if 'csrf' not in session: session['csrf']=secrets.token_hex(32)
    if request.method=='POST' and not secrets.compare_digest(session['csrf'],request.form.get('csrf','')): abort(403)
    if request.method=='POST' and request.path in ('/login','/register'):
        now=time.monotonic()
        with auth_lock:
            auth_window[:]=[t for t in auth_window if now-t<60]
            if len(auth_window)>=20: abort(429)
            auth_window.append(now)
@app.after_request
def headers(r):
    r.headers['X-Content-Type-Options']='nosniff'; r.headers['X-Frame-Options']='DENY'; r.headers['Referrer-Policy']='no-referrer'; r.headers['Content-Security-Policy']="default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"; r.headers['Cache-Control']='no-store'; return r
@app.get('/')
def home():
    q=request.args.get('q','')[:100]; notes=[]
    if session.get('uid'):
        with closing(db()) as c: notes=c.execute('SELECT * FROM notes WHERE owner=? AND title LIKE ? ORDER BY id DESC LIMIT 100',(session['uid'],'%'+q+'%')).fetchall()
    return render_template('index.html',notes=notes,q=q)
@app.get('/health')
def health():
    return jsonify(status='ok')
@app.post('/register')
def register():
    u=request.form.get('username','').strip(); p=request.form.get('password','')
    if not 3<=len(u)<=32 or not 12<=len(p)<=128: return 'Username: 3–32; password: 12–128 characters.',400
    try:
        with closing(db()) as c,c:
            c.execute('BEGIN IMMEDIATE')
            if c.execute('SELECT COUNT(*) FROM users').fetchone()[0]>=500: abort(429)
            c.execute('INSERT INTO users(username,password) VALUES(?,?)',(u,generate_password_hash(p)))
    except sqlite3.IntegrityError: return 'Account unavailable.',409
    return redirect(url_for('home'))
@app.post('/login')
def login():
    u=request.form.get('username','')[:32]; p=request.form.get('password','')[:128]
    with closing(db()) as c: row=c.execute('SELECT * FROM users WHERE username=?',(u,)).fetchone()
    if not row or not check_password_hash(row['password'],p): return 'Invalid credentials.',401
    session.clear(); session.update(uid=row['id'],username=row['username'],csrf=secrets.token_hex(32)); return redirect(url_for('home'))
@app.post('/logout')
def logout():
    session.clear(); return redirect(url_for('home'))
@app.post('/notes')
def add():
    if not session.get('uid'): abort(401)
    title=request.form.get('title','').strip(); body=request.form.get('body','')
    if not 1<=len(title)<=100 or len(body)>2000: abort(400)
    with closing(db()) as c,c:
        c.execute('BEGIN IMMEDIATE')
        if c.execute('SELECT COUNT(*) FROM notes WHERE owner=?',(session['uid'],)).fetchone()[0]>=100: abort(429)
        c.execute('INSERT INTO notes(owner,title,body) VALUES(?,?,?)',(session['uid'],title,body))
    return redirect(url_for('home'))
@app.post('/notes/<int:note_id>/delete')
def delete(note_id):
    if not session.get('uid'): abort(401)
    with closing(db()) as c,c:
        if not c.execute('DELETE FROM notes WHERE id=? AND owner=?',(note_id,session['uid'])).rowcount: abort(404)
    return redirect(url_for('home'))
@app.get('/api/notes')
def api():
    if not session.get('uid'): abort(401)
    with closing(db()) as c: return jsonify([dict(r) for r in c.execute('SELECT id,title,body FROM notes WHERE owner=? LIMIT 100',(session['uid'],))])
if __name__=='__main__': app.run(host='127.0.0.1',port=5000)

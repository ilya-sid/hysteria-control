import os, sqlite3, secrets, subprocess, re, json, urllib.request, urllib.parse, sys, hashlib, base64, grp, time
from flask import Flask, request, session, redirect, abort, make_response, Response

APP_DIR=os.environ.get('HY_CONTROL_DIR','/opt/hysteria-control')
DB=os.environ.get('PANEL_DB',os.path.join(APP_DIR,'panel.db'))
DOMAIN=os.environ['PANEL_DOMAIN']
API=os.environ.get('HYSTERIA_API','http://127.0.0.1:9999')
API_SECRET_FILE=os.environ.get('HYSTERIA_API_SECRET_FILE','/etc/hysteria/api-secret')
HY2_CONFIG=os.environ.get('HYSTERIA_CONFIG','/etc/hysteria/config.yaml')
PANEL_CERT=os.environ.get('PANEL_CERT','/etc/letsencrypt/live/'+DOMAIN+'/fullchain.pem')
PANEL_KEY=os.environ.get('PANEL_KEY','/etc/letsencrypt/live/'+DOMAIN+'/privkey.pem')
PANEL_PORT=int(os.environ.get('PANEL_PORT','8443'))
app=Flask(__name__); app.secret_key=os.environ['PANEL_SECRET']
app.config.update(SESSION_COOKIE_SECURE=True,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax')
last_cpu=None; last_net=None; last_sample=0
db_ready=False

def conn():
    global db_ready
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
    if not db_ready:
        c.execute('create table if not exists users(username text primary key,password text not null,enabled integer not null default 1)')
        c.execute('create table if not exists usage(username text primary key,tx integer not null default 0,rx integer not null default 0,last_tx integer not null default 0,last_rx integer not null default 0)')
        c.execute('create table if not exists settings(key text primary key,value text not null)')
        c.commit(); db_ready=True
    return c
def setting(key,default=''):
    c=conn(); r=c.execute('select value from settings where key=?',(key,)).fetchone(); c.close(); return r['value'] if r else default
def put_setting(key,value):
    c=conn(); c.execute('insert into settings values(?,?) on conflict(key) do update set value=excluded.value',(key,value)); c.commit(); c.close()
def hash_password(password):
    salt=secrets.token_bytes(16); rounds=310000
    digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,rounds)
    return f'pbkdf2_sha256${rounds}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}'
def verify_password(password,encoded):
    try:
        scheme,rounds,salt,digest=encoded.split('$',3)
        rounds=int(rounds)
        if scheme!='pbkdf2_sha256' or not 100000<=rounds<=1000000: return False
        candidate=hashlib.pbkdf2_hmac('sha256',password.encode(),base64.urlsafe_b64decode(salt),rounds)
        return secrets.compare_digest(base64.urlsafe_b64encode(candidate).decode(),digest)
    except (ValueError,TypeError): return False
def admin_password_matches(password):
    stored=setting('admin_password_hash')
    if stored: return verify_password(password,stored)
    return secrets.compare_digest(password,os.environ['PANEL_PASS'])
def auth_version(): return setting('admin_auth_version','legacy')
def api_get(path):
    with open(API_SECRET_FILE) as f: secret=f.read().strip()
    req=urllib.request.Request(API+path,headers={'Authorization':secret})
    with urllib.request.urlopen(req,timeout=2) as r: return json.loads(r.read())
def record_traffic():
    try: traffic=api_get('/traffic')
    except Exception: return
    c=conn()
    changed=False
    for name,v in traffic.items():
        owner=c.execute('select username from users where username=? collate nocase',(name,)).fetchone()
        if not owner: continue
        name=owner['username']
        tx=max(0,int(v.get('tx',0))); rx=max(0,int(v.get('rx',0)))
        old=c.execute('select tx,rx,last_tx,last_rx from usage where username=?',(name,)).fetchone()
        if old:
            if tx==old['last_tx'] and rx==old['last_rx']: continue
            addtx=tx-old['last_tx'] if tx>=old['last_tx'] else tx
            addrx=rx-old['last_rx'] if rx>=old['last_rx'] else rx
            c.execute('update usage set tx=tx+?,rx=rx+?,last_tx=?,last_rx=? where username=?',(max(0,addtx),max(0,addrx),tx,rx,name))
        else: c.execute('insert into usage(username,tx,rx,last_tx,last_rx) values(?,?,?,?,?)',(name,tx,rx,tx,rx))
        changed=True
    if changed: c.commit()
    c.close()
def write_server_config():
    record_traffic()
    c=conn(); rows=c.execute('select username,password from users where enabled=1 order by username').fetchall(); c.close()
    if not rows: raise ValueError('At least one Hysteria user must remain enabled')
    with open(API_SECRET_FILE) as f: api_secret=f.read().strip()
    lines=['listen: :443','tls:','  cert: '+PANEL_CERT,'  key: '+PANEL_KEY,'auth:','  type: userpass','  userpass:']
    lines += [f'    {r["username"]}: {r["password"]}' for r in rows]
    lines += ['trafficStats:','  listen: 127.0.0.1:9999','  secret: '+api_secret,'masquerade:','  type: proxy','  proxy:','    url: https://www.bing.com/','    rewriteHost: true']
    os.makedirs(os.path.dirname(HY2_CONFIG),exist_ok=True)
    p=HY2_CONFIG; tmp=p+'.tmp'
    with open(tmp,'w') as f: f.write('\n'.join(lines)+'\n')
    os.chown(tmp,0,grp.getgrnam('hysteria-control').gr_gid)
    os.chmod(tmp,0o640); os.replace(tmp,p)
    subprocess.run(['systemctl','restart','hysteria-server'],check=True)

def sync():
    subprocess.run(['/usr/bin/sudo','-n','/usr/local/sbin/hysteria-control-sync'],check=True)

def page(body):
    light=request.cookies.get('theme')=='light'
    css='''*{box-sizing:border-box}body{margin:0;font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:var(--bg);color:var(--text);transition:background .2s,color .2s}:root{color-scheme:dark;--bg:#050505;--panel:#0d0d0f;--card:#111113;--card2:#171719;--text:#f4f4f5;--muted:#8a8a91;--border:#252529;--accent:#e6532f;--accent2:#c94120;--accent-light:#ff8b67;--good:#35d39a;--bad:#ff647c;--input:#0b0b0d;--shadow:0 14px 42px #0008}body.light{color-scheme:light;--bg:#f4f6fa;--panel:#fff;--card:#fff;--card2:#f8f9fc;--text:#19202e;--muted:#697386;--border:#e4e8ef;--accent:#c94120;--accent2:#b73719;--accent-light:#e6532f;--good:#13966a;--bad:#dc4357;--input:#fff;--shadow:0 12px 30px #1d2a4410}a{color:inherit;text-decoration:none}button,input{font:inherit}button{border:1px solid var(--border);border-radius:10px;padding:9px 13px;background:var(--card2);color:var(--text);cursor:pointer;transition:.15s}button:hover{border-color:var(--accent);transform:translateY(-1px)}button.primary{background:var(--accent2);border-color:var(--accent2);color:white}button.danger{color:var(--bad)}input{border:1px solid var(--border);border-radius:10px;padding:10px 12px;background:var(--input);color:var(--text);outline:none}input:focus{border-color:var(--accent)}.shell{max-width:1180px;margin:auto;padding:28px 22px 60px}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}.brand{display:flex;gap:12px;align-items:center}.logo{width:38px;height:38px;border-radius:12px;background:linear-gradient(145deg,var(--accent-light),var(--accent2));display:grid;place-items:center;color:white;font-weight:800;font-size:18px}.brand h1{font-size:18px;margin:0;letter-spacing:-.3px}.brand small{display:block;color:var(--muted);font-size:12px}.top-actions{display:flex;align-items:center;gap:9px}.theme{width:38px;height:38px;border-radius:12px;display:grid;place-items:center}.hero{display:flex;justify-content:space-between;align-items:end;margin:12px 0 20px}.hero h2{font-size:25px;letter-spacing:-.8px;margin:0}.hero p{margin:5px 0 0;color:var(--muted)}.live{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:12px}.lamp{width:9px;height:9px;border-radius:50%;background:var(--good);box-shadow:0 0 0 4px color-mix(in srgb,var(--good) 16%,transparent),0 0 13px color-mix(in srgb,var(--good) 65%,transparent);display:inline-block}.lamp.off{background:var(--bad);box-shadow:0 0 0 4px color-mix(in srgb,var(--bad) 16%,transparent),0 0 13px color-mix(in srgb,var(--bad) 55%,transparent)}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:17px;box-shadow:var(--shadow)}.metric .label{color:var(--muted);font-size:12px}.metric strong{display:block;font-size:22px;letter-spacing:-.5px;margin-top:6px;font-weight:650}.metric .sub{font-size:11px;color:var(--muted);margin-top:3px}.section-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:27px 0 12px}.section-head h3{font-size:16px;margin:0;letter-spacing:-.2px}.section-head p{font-size:12px;color:var(--muted);margin:3px 0 0}.server-card{margin-top:13px}.bar{height:4px;background:var(--border);border-radius:5px;margin-top:12px;overflow:hidden}.bar i{height:100%;display:block;width:0;background:linear-gradient(90deg,var(--accent2),var(--accent-light));border-radius:5px;transition:width .4s}.server-row{display:flex;justify-content:space-between;gap:18px;align-items:center}.server-info{display:flex;gap:14px;align-items:center}.server-info h3{font-size:14px;margin:0}.server-info p{font-size:12px;color:var(--muted);margin:2px 0}.client{display:grid;grid-template-columns:minmax(190px,1fr) minmax(180px,1fr) auto;align-items:center;gap:16px;padding:14px 0;border-top:1px solid var(--border)}.client:first-child{border-top:0}.client-name{display:flex;align-items:center;gap:10px;font-weight:600}.client-meta{font-size:11px;color:var(--muted);margin:3px 0 0 19px}.traffic{font-variant-numeric:tabular-nums;color:var(--muted);font-size:12px}.traffic b{color:var(--text);font-weight:550}.actions{display:flex;gap:7px;justify-content:end;flex-wrap:wrap}.small{font-size:12px;padding:7px 9px}.link{margin-top:9px;padding:9px 11px;border-radius:10px;border:1px solid var(--border);background:var(--input);font:11px/1.5 ui-monospace,SFMono-Regular,monospace;overflow-wrap:anywhere;color:var(--muted)}.client-lower{grid-column:1/-1;display:grid;grid-template-columns:1fr auto;gap:10px;align-items:center}.qr{width:112px;height:112px;background:white;padding:7px;border-radius:10px;display:none}.qr.open{display:block}.qr-wrap{display:flex;justify-content:end}.form-row{display:flex;gap:8px;flex-wrap:wrap}.form-row input{min-width:210px;flex:1}.sni-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.sni-row input{width:min(350px,100%)}.muted{color:var(--muted)}.statusline{display:flex;align-items:center;gap:8px}.pill{font-size:11px;border:1px solid var(--border);border-radius:999px;padding:4px 8px;color:var(--muted)}.footer-note{margin-top:14px;color:var(--muted);font-size:11px}.login{max-width:400px;margin:10vh auto}.login input{width:100%;margin:6px 0}.empty{padding:24px;color:var(--muted);text-align:center}@media(max-width:800px){.grid{grid-template-columns:repeat(2,1fr)}.client{grid-template-columns:1fr auto}.traffic{grid-column:1}.actions{grid-column:2;grid-row:1/3}.client-lower{grid-template-columns:1fr auto}}@media(max-width:520px){.shell{padding:18px 13px 45px}.hero{align-items:start;flex-direction:column;gap:10px}.server-row{align-items:start;flex-direction:column}.grid{gap:8px}.card{padding:13px}.metric strong{font-size:19px}.client{gap:8px}.actions{flex-direction:column}.link{font-size:10px}}
'''
    css+='''.password-menu{position:relative}.password-popover{position:absolute;right:0;top:calc(100% + 10px);z-index:20;width:min(380px,calc(100vw - 28px));padding:18px}.password-popover[hidden]{display:none}.password-popover h3{font-size:15px;margin:0 0 4px}.password-popover p{font-size:12px;margin:0 0 12px}.password-popover form{display:grid;gap:9px}.password-popover input,.password-popover form button{width:100%}@media(max-width:520px){.top-actions{gap:6px}.password-menu>button{font-size:12px;padding:9px}}'''
    theme='light' if light else 'dark'
    script='''
const themeBtn=document.getElementById('themeToggle');if(themeBtn)themeBtn.onclick=()=>{let v=document.body.classList.contains('light')?'dark':'light';document.cookie='theme='+v+';path=/;max-age=31536000';location.reload()};
const passwordBtn=document.getElementById('passwordToggle'),passwordPanel=document.getElementById('passwordPanel');if(passwordBtn&&passwordPanel){passwordBtn.onclick=()=>{passwordPanel.hidden=!passwordPanel.hidden;passwordBtn.setAttribute('aria-expanded',String(!passwordPanel.hidden))};document.addEventListener('click',e=>{if(!e.target.closest('.password-menu')){passwordPanel.hidden=true;passwordBtn.setAttribute('aria-expanded','false')}});document.addEventListener('keydown',e=>{if(e.key==='Escape'){passwordPanel.hidden=true;passwordBtn.setAttribute('aria-expanded','false')}})}
function fmt(b){if(!Number.isFinite(b))return '—';let u=['Б','КБ','МБ','ГБ','ТБ'],i=0;while(b>=1024&&i<u.length-1){b/=1024;i++}return (i?b.toFixed(1):Math.round(b))+' '+u[i]}
function upd(){fetch('/api/metrics').then(r=>r.json()).then(d=>{document.querySelectorAll('[data-metric]').forEach(e=>{let k=e.dataset.metric;if(k in d)e.textContent=d[k]});let a=document.getElementById('serviceLamp');if(a){a.classList.toggle('off',!d.service);document.getElementById('serviceText').textContent=d.service?'Работает':'Остановлена';let a2=document.getElementById('serviceLamp2');if(a2)a2.classList.toggle('off',!d.service)}if(d.resources){for(let k of ['ram','swap','disk']){let e=document.getElementById(k+'Bar');if(e)e.style.width=d.resources[k].percent+'%'}}if(d.users)for(let [u,x] of Object.entries(d.users)){let c=document.querySelector('[data-user="'+CSS.escape(u)+'"]');if(!c)continue;let lamp=c.querySelector('.userlamp');lamp.classList.toggle('off',!(x.online>0)||!x.enabled);c.querySelector('[data-traffic="tx"]').textContent=fmt(x.tx);c.querySelector('[data-traffic="rx"]').textContent=fmt(x.rx);c.querySelector('[data-online]').textContent=x.online>0?'Активно':'Не в сети'}}).catch(()=>{})}upd();setInterval(upd,15000);
function qr(btn){let box=btn.closest('.client').querySelector('.qr');if(!box.dataset.loaded){box.src=btn.dataset.qr;box.dataset.loaded='1'}box.classList.toggle('open')}
function copyLink(btn){navigator.clipboard.writeText(btn.dataset.link);let t=btn.textContent;btn.textContent='Скопировано';setTimeout(()=>btn.textContent=t,1300)}
'''
    html='<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Hysteria Control</title><style>__CSS__</style></head><body class="__THEME__"><div class=shell>__BODY__</div><script>__SCRIPT__</script></body></html>'
    html=html.replace('__CSS__',css).replace('__THEME__',theme).replace('__BODY__',body).replace('__SCRIPT__',script)
    return make_response(html)

def logged(): return session.get('ok') is True and session.get('auth_version')==auth_version()
def csrf():
    if 'csrf' not in session: session['csrf']=secrets.token_hex(16)
    return session['csrf']
def valid_csrf():
    token=request.form.get('csrf')
    expected=session.get('csrf')
    return bool(token and expected and secrets.compare_digest(token,expected))
def check():
    if not valid_csrf(): abort(400)

LOGIN='''<div class="top"><div class="brand"><div class=logo>H</div><div><h1>Hysteria Control</h1><small>Личный сервер</small></div></div><button class=theme id=themeToggle title="Сменить тему">◐</button></div><div class="card login"><h2>Вход в панель</h2><p class=muted>Управление сервером и доступом пользователей</p><form method=post><input name=user placeholder="Логин" required><input name=password type=password placeholder="Пароль" required><button class=primary style="width:100%;margin-top:8px">Войти</button></form></div>'''

@app.route('/',methods=['GET','POST'])
def home():
    if request.method=='POST':
        password=request.form.get('password','')
        if request.form.get('user')==os.environ['PANEL_USER'] and admin_password_matches(password):
            if not setting('admin_password_hash'): put_setting('admin_password_hash',hash_password(password))
            session['ok']=True; session['auth_version']=auth_version(); return redirect('/')
        return page(LOGIN.replace('Личный сервер','Неверный логин или пароль'))
    if not logged(): return page(LOGIN)
    c=conn(); users=c.execute('select username,password,enabled from users order by username').fetchall(); c.close()
    sni=setting('sni',DOMAIN); tok=csrf()
    password_menu=f'''<div class=password-menu><button type=button id=passwordToggle aria-expanded=false aria-controls=passwordPanel>Пароль</button><div class="card password-popover" id=passwordPanel hidden><h3>Смена пароля</h3><p class=muted>Введите текущий и новый пароль.</p><form method=post action=/password><input type=hidden name=csrf value="{tok}"><input type=password name=current_password placeholder="Текущий пароль" autocomplete=current-password required><input type=password name=new_password placeholder="Новый пароль (от 12 символов)" autocomplete=new-password minlength=12 maxlength=256 required><input type=password name=confirm_password placeholder="Повторите новый пароль" autocomplete=new-password minlength=12 maxlength=256 required><button class=primary>Сменить пароль</button></form></div></div>'''
    body=f'''<header class=top><div class=brand><div class=logo>H</div><div><h1>Hysteria Control</h1><small>Панель управления сервером</small></div></div><div class=top-actions><button class=theme id=themeToggle title="Сменить тему">◐</button>{password_menu}<a href=/logout><button>Выйти</button></a></div></header>
<div class=hero><div><h2>Обзор сервера</h2><p>Состояние узла и активность подключений</p></div><div class=live><span class="lamp" id=serviceLamp></span><span id=serviceText>Проверяем сервер</span><span class=pill>обновление каждые 15 сек</span></div></div>
<div class=grid><div class="card metric"><div class=label>Нагрузка на процессор</div><strong><span data-metric=cpu>—</span></strong><div class=sub>текущая загрузка CPU</div></div><div class="card metric"><div class=label>Оперативная память</div><strong><span data-metric=ram>—</span></strong><div class=bar><i id=ramBar></i></div></div><div class="card metric"><div class=label>Swap</div><strong><span data-metric=swap>—</span></strong><div class=bar><i id=swapBar></i></div></div><div class="card metric"><div class=label>Диск</div><strong><span data-metric=disk>—</span></strong><div class=bar><i id=diskBar></i></div></div></div>
<section class="card server-card"><div class=server-row><div class=server-info><span class=lamp id=serviceLamp2></span><div><h3>Hysteria2</h3><p>UDP/443 · {DOMAIN}</p></div></div><form method=post action=/sni><input type=hidden name=csrf value="{tok}"><div class=sni-row><input name=sni value="{sni}" aria-label="SNI"><button class=small>Сохранить SNI</button></div></form></div></section>
<div class=section-head><div><h3>Пользователи</h3><p>Индивидуальные подключения и их трафик</p></div><span class=pill>{len(users)} всего</span></div>
<section class=card><form class=form-row method=post action=/add><input type=hidden name=csrf value="{tok}"><input name=u placeholder="Имя нового пользователя" pattern="[A-Za-z0-9_-]{{1,32}}" maxlength=32 required><button class=primary>＋ Добавить пользователя</button></form><div style="margin-top:14px">'''
    if not users: body+='<div class=empty>Пока нет пользователей. Добавьте первого выше.</div>'
    for u in users:
        name=u['username']; uri=f'hysteria2://{name}:{u["password"]}@{DOMAIN}:443/?sni={sni}&insecure=0#{name}'
        state='Включён' if u['enabled'] else 'Отключён'
        qrurl='/qr/'+urllib.parse.quote(name,safe='')
        body+=f'''<div class=client data-user="{name}"><div><div class=client-name><span class="lamp userlamp {'off' if not u['enabled'] else ''}"></span>{name}<span class=pill>{state}</span></div><div class=client-meta data-online>Сверяем соединение…</div></div><div class=traffic>Скачано <b data-traffic=tx>—</b><br>Загружено <b data-traffic=rx>—</b></div><div class=actions><button class=small onclick="qr(this)" data-qr="{qrurl}">QR-код</button><button class=small onclick="copyLink(this)" data-link="{uri}">Копировать</button><form method=post action=/toggle><input type=hidden name=csrf value="{tok}"><input type=hidden name=u value="{name}"><button class="small">{'Отключить' if u['enabled'] else 'Включить'}</button></form><form method=post action=/delete onsubmit="return confirm('Удалить пользователя {name}?')"><input type=hidden name=csrf value="{tok}"><input type=hidden name=u value="{name}"><button class="small danger">Удалить</button></form></div><div class=client-lower><div class=link>{uri}</div><div class=qr-wrap><img class=qr alt="QR код подключения"></div></div></div>'''
    body+='''</div></section><div class=footer-note>Индикатор показывает текущую сессию Hysteria2. Трафик — накопительно с момента добавления пользователя.</div>'''
    return page(body)

@app.route('/password',methods=['GET','POST'])
def change_password():
    if request.method=='GET': return redirect('/')
    if not logged(): abort(403)
    check()
    current=request.form.get('current_password','')
    new=request.form.get('new_password','')
    confirm=request.form.get('confirm_password','')
    if not admin_password_matches(current):
        return page('<div class="card login"><h2>Текущий пароль неверен</h2><a href="/"><button>Назад</button></a></div>')
    if len(new)<12 or len(new)>256:
        return page('<div class="card login"><h2>Пароль должен содержать от 12 до 256 символов</h2><a href="/"><button>Назад</button></a></div>')
    if not secrets.compare_digest(new,confirm):
        return page('<div class="card login"><h2>Новые пароли не совпадают</h2><a href="/"><button>Назад</button></a></div>')
    put_setting('admin_password_hash',hash_password(new))
    put_setting('admin_auth_version',secrets.token_urlsafe(24))
    session.clear()
    return page('<div class="card login"><h2>Пароль изменён</h2><p class=muted>Войдите снова с новым паролем.</p><a href="/"><button class=primary>Перейти ко входу</button></a></div>')

@app.route('/add',methods=['GET','POST'])
def add():
    if request.method=='GET': return redirect('/')
    if not logged(): abort(403)
    if not valid_csrf():
        return page('<div class="card login"><h2>Форма устарела</h2><p class=muted>Обновите страницу и добавьте пользователя ещё раз.</p><a href="/"><button>Вернуться в панель</button></a></div>')
    u=request.form.get('u','').strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,32}',u):
        return page('<div class="card login"><h2>Неверное имя пользователя</h2><p class=muted>Используйте 1–32 латинские буквы, цифры, _ или -.</p><a href="/"><button>Вернуться в панель</button></a></div>')
    c=conn()
    if c.execute('select 1 from users where username=? collate nocase',(u,)).fetchone():
        c.close(); return page('<div class="card login"><h2>Пользователь уже существует</h2><p class=muted>Выберите другое имя.</p><a href="/"><button>Вернуться в панель</button></a></div>')
    try: c.execute('insert into users(username,password,enabled) values(?,?,1)',(u,secrets.token_urlsafe(20))); c.commit()
    except sqlite3.IntegrityError:
        c.close(); return page('<div class="card login"><h2>Пользователь уже существует</h2><p class=muted>Выберите другое имя.</p><a href="/"><button>Вернуться в панель</button></a></div>')
    c.close(); sync(); return redirect('/')
@app.route('/toggle',methods=['GET','POST'])
def toggle():
    if request.method=='GET': return redirect('/')
    if not logged(): abort(403)
    check(); c=conn()
    target=c.execute('select enabled from users where username=?',(request.form.get('u'),)).fetchone()
    if target and target['enabled'] and c.execute('select count(*) from users where enabled=1').fetchone()[0]<=1:
        c.close(); return page('<div class="card login"><h2>Нужен хотя бы один активный пользователь</h2><a href="/"><button>Назад</button></a></div>')
    c.execute('update users set enabled=1-enabled where username=?',(request.form.get('u'),)); c.commit(); c.close(); sync(); return redirect('/')
@app.route('/delete',methods=['GET','POST'])
def delete():
    if request.method=='GET': return redirect('/')
    if not logged(): abort(403)
    check(); username=request.form.get('u'); record_traffic(); c=conn()
    target=c.execute('select enabled from users where username=?',(username,)).fetchone()
    if target and target['enabled'] and c.execute('select count(*) from users where enabled=1').fetchone()[0]<=1:
        c.close(); return page('<div class="card login"><h2>Нужен хотя бы один активный пользователь</h2><a href="/"><button>Назад</button></a></div>')
    c.execute('delete from users where username=?',(username,)); c.commit(); c.close(); sync(); return redirect('/')
@app.route('/sni',methods=['GET','POST'])
def sni():
    if request.method=='GET': return redirect('/')
    if not logged(): abort(403)
    check(); value=request.form.get('sni','').strip().lower()
    if value!=DOMAIN: return page('<div class="card">SNI должен совпадать с доменом TLS-сертификата: '+DOMAIN+'.</div><a href="/"><button>Назад</button></a>')
    put_setting('sni',value); return redirect('/')

@app.get('/qr/<username>')
def qr(username):
    if not logged(): abort(403)
    c=conn(); u=c.execute('select username,password,enabled from users where username=?',(username,)).fetchone(); c.close()
    if not u: abort(404)
    uri=f'hysteria2://{username}:{u["password"]}@{DOMAIN}:443/?sni={setting("sni",DOMAIN)}&insecure=0#{username}'
    p=subprocess.run(['qrencode','-t','PNG','-o','-','-s','6','-m','2'],input=uri.encode(),capture_output=True,check=True)
    return Response(p.stdout,mimetype='image/png',headers={'Cache-Control':'no-store'})

def cpu_counters():
    a=list(map(int,open('/proc/stat').readline().split()[1:])); return sum(a),sum(a[3:5])
def resources():
    global last_cpu,last_net,last_sample
    m={}
    for line in open('/proc/meminfo'):
        k,v=line.split(':',1); m[k]=int(v.strip().split()[0])
    total=m.get('MemTotal',0); avail=m.get('MemAvailable',0); st=m.get('SwapTotal',0); sf=m.get('SwapFree',0)
    d=subprocess.check_output(['df','-Pk','/'],text=True).splitlines()[1].split(); du,dt=int(d[2]),int(d[1])
    cpu=cpu_counters()
    if last_cpu is None:
        time.sleep(0.1)
        last_cpu=cpu
        cpu=cpu_counters()
    total_delta=cpu[0]-last_cpu[0]
    idle_delta=cpu[1]-last_cpu[1]
    cpu_pct=max(0,min(100,100*(1-idle_delta/max(1,total_delta))))
    last_cpu=cpu
    result={'cpu':f'{cpu_pct:.0f}%', 'ram':f'{(total-avail)/1024:.0f} / {total/1024:.0f} МБ','swap':f'{(st-sf)/1024:.0f} / {st/1024:.0f} МБ','disk':f'{du/1024:.0f} / {dt/1024:.0f} МБ','resources':{'ram':{'percent':round(100*(total-avail)/max(1,total))},'swap':{'percent':round(100*(st-sf)/max(1,st))},'disk':{'percent':int(d[4].rstrip('%'))}}}
    return result
@app.get('/api/metrics')
def metrics():
    if not logged(): abort(403)
    data=resources()
    try: online=api_get('/online'); record_traffic(); data['service']=True
    except Exception: online={}; data['service']=False
    c=conn(); rows=c.execute('select u.username,u.enabled,coalesce(s.tx,0),coalesce(s.rx,0) from users u left join usage s using(username)').fetchall(); c.close()
    online_by_name={str(name).lower():int(count) for name,count in online.items()}
    data['users']={r['username']:{'online':online_by_name.get(r['username'].lower(),0) if r['enabled'] else 0,'tx':int(r[2]),'rx':int(r[3]),'enabled':bool(r['enabled'])} for r in rows}
    return data
@app.get('/logout')
def logout(): session.clear(); return redirect('/')
if __name__=='__main__':
    if sys.argv[1:]==['--sync-root']:
        write_server_config()
    else:
        app.run(host='0.0.0.0',port=PANEL_PORT,ssl_context=(PANEL_CERT,PANEL_KEY))

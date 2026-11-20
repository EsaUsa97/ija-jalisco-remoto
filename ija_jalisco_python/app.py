import os
import time
import hashlib
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024  # Máx 25 MB por archivo
JWT_SECRET = os.getenv('JWT_SECRET', 'IJA_JALISCO_SECRETO_INSTITUCIONAL_2026')
DATABASE_URL = os.getenv('DATABASE_URL', '').strip()
USAR_POSTGRES = DATABASE_URL.startswith('postgres://') or DATABASE_URL.startswith('postgresql://')

if USAR_POSTGRES:
    import psycopg
    from psycopg.rows import dict_row

DB_PATH = 'ija_local.db'
BOVEDA_DIR = os.getenv('BOVEDA_DIR', 'boveda_evidencias')
os.makedirs(BOVEDA_DIR, exist_ok=True)

EXTENSIONES_PERMITIDAS = {'pdf', 'jpg', 'jpeg', 'png', 'webm', 'mp4', 'mp3', 'wav'}
intentos_login = {}

def extension_valida(nombre_archivo):
    return '.' in nombre_archivo and nombre_archivo.rsplit('.', 1)[1].lower() in EXTENSIONES_PERMITIDAS

def sql(query):
    return query.replace('?', '%s') if USAR_POSTGRES else query

def get_db():
    if USAR_POSTGRES:
        url = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
        return psycopg.connect(url, row_factory=dict_row)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    pk = 'SERIAL PRIMARY KEY' if USAR_POSTGRES else 'INTEGER PRIMARY KEY AUTOINCREMENT'
    tablas = [
        f'''CREATE TABLE IF NOT EXISTS usuarios (
            id {pk},
            nombre TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            rol TEXT NOT NULL,
            edad INTEGER,
            municipio TEXT,
            acepto_terminos INTEGER DEFAULT 1,
            fecha_aceptacion TEXT
        )''',
        f'''CREATE TABLE IF NOT EXISTS expedientes (
            id {pk},
            folio TEXT UNIQUE NOT NULL,
            ciudadano_id INTEGER NOT NULL,
            telefono TEXT,
            movilidad TEXT,
            materia TEXT,
            relato TEXT,
            contraparte TEXT,
            estatus TEXT DEFAULT 'En revisión por abogado',
            cita TEXT,
            acta_legal TEXT,
            firma_base64 TEXT,
            creado_en TEXT
        )''',
        f'''CREATE TABLE IF NOT EXISTS pruebas (
            id {pk},
            expediente_id INTEGER NOT NULL,
            codigo_prueba TEXT NOT NULL,
            tipo TEXT,
            nombre_archivo TEXT NOT NULL,
            ruta_guardada TEXT NOT NULL,
            hash_sha256 TEXT NOT NULL,
            subido_en TEXT
        )''',
        f'''CREATE TABLE IF NOT EXISTS mensajes (
            id {pk},
            expediente_id INTEGER NOT NULL,
            autor_nombre TEXT NOT NULL,
            emisor_rol TEXT NOT NULL,
            contenido TEXT NOT NULL,
            enviado_en TEXT
        )''',
        f'''CREATE TABLE IF NOT EXISTS auditoria (
            id {pk},
            usuario_email TEXT,
            accion TEXT,
            ip TEXT,
            fecha TEXT
        )'''
    ]
    for t in tablas:
        cur.execute(t)
    conn.commit()
    conn.close()

init_db()

@app.after_request
def aplicar_cabeceras_seguridad(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

def registrar_auditoria(email, accion):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        sql('INSERT INTO auditoria (usuario_email, accion, ip, fecha) VALUES (?, ?, ?, ?)'),
        (email, accion, request.remote_addr, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

def requiere_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Token requerido'}), 401
        token = auth.split(' ')[1]
        try:
            request.usuario = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        except Exception:
            return jsonify({'error': 'Sesión expirada o inválida'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'ok',
        'motor_bd': 'PostgreSQL (Nube)' if USAR_POSTGRES else 'SQLite (Local)',
        'boveda': BOVEDA_DIR
    })

@app.route('/api/auth/registro', methods=['POST'])
def registro():
    data = request.json or {}
    nombre = (data.get('nombre') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    rol = data.get('rol', 'ciudadano')

    if not nombre or not email or len(password) < 4:
        return jsonify({'error': 'Datos incompletos o contraseña muy corta'}), 400

    conn = get_db()
    cur = conn.cursor()
    try:
        ahora = datetime.now().isoformat()
        if USAR_POSTGRES:
            cur.execute(
                'INSERT INTO usuarios (nombre, email, password_hash, rol, edad, municipio, acepto_terminos, fecha_aceptacion) VALUES (%s, %s, %s, %s, %s, %s, 1, %s) RETURNING id',
                (nombre, email, generate_password_hash(password), rol, data.get('edad'), data.get('municipio'), ahora)
            )
            user_id = cur.fetchone()['id']
        else:
            cur.execute(
                'INSERT INTO usuarios (nombre, email, password_hash, rol, edad, municipio, acepto_terminos, fecha_aceptacion) VALUES (?, ?, ?, ?, ?, ?, 1, ?)',
                (nombre, email, generate_password_hash(password), rol, data.get('edad'), data.get('municipio'), ahora)
            )
            user_id = cur.lastrowid

        if rol == 'ciudadano':
            folio = f"IJA-JAL-2026-{user_id:04d}"
            cur.execute(
                sql('INSERT INTO expedientes (folio, ciudadano_id, creado_en) VALUES (?, ?, ?)'),
                (folio, user_id, ahora)
            )
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        return jsonify({'error': 'Este correo ya está registrado'}), 409

    usuario = {'id': user_id, 'nombre': nombre, 'email': email, 'rol': rol}
    token = jwt.encode({**usuario, 'exp': datetime.utcnow() + timedelta(hours=8)}, JWT_SECRET, algorithm='HS256')
    conn.close()
    registrar_auditoria(email, f'REGISTRO_ACEPTACION_LEGAL ({rol})')
    return jsonify({'token': token, 'usuario': usuario})

@app.route('/api/auth/login', methods=['POST'])
def login():
    ip = request.remote_addr
    ahora = time.time()
    registro_ip = intentos_login.get(ip, {'conteo': 0, 'bloqueo_hasta': 0})

    if ahora < registro_ip['bloqueo_hasta']:
        return jsonify({'error': 'Demasiados intentos fallidos. Espere 1 minuto por seguridad.'}), 429

    data = request.json or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql('SELECT * FROM usuarios WHERE email = ?'), (email,))
    user = cur.fetchone()
    conn.close()

    if not user or not check_password_hash(user['password_hash'], password):
        registro_ip['conteo'] += 1
        if registro_ip['conteo'] >= 5:
            registro_ip['bloqueo_hasta'] = ahora + 60
            registro_ip['conteo'] = 0
        intentos_login[ip] = registro_ip
        registrar_auditoria(email, 'LOGIN_FALLIDO')
        return jsonify({'error': 'Credenciales incorrectas'}), 401

    intentos_login[ip] = {'conteo': 0, 'bloqueo_hasta': 0}
    usuario = {'id': user['id'], 'nombre': user['nombre'], 'email': user['email'], 'rol': user['rol']}
    token = jwt.encode({**usuario, 'exp': datetime.utcnow() + timedelta(hours=8)}, JWT_SECRET, algorithm='HS256')
    registrar_auditoria(email, 'LOGIN_EXITOSO')
    return jsonify({'token': token, 'usuario': usuario})

@app.route('/api/expedientes', methods=['GET'])
@requiere_auth
def listar_expedientes():
    conn = get_db()
    cur = conn.cursor()
    if request.usuario['rol'] == 'abogado':
        cur.execute('''
            SELECT e.*, u.nombre as ciudadano_nombre, u.edad, u.municipio
            FROM expedientes e JOIN usuarios u ON e.ciudadano_id = u.id
            ORDER BY e.id DESC
        ''')
    else:
        cur.execute(sql('''
            SELECT e.*, u.nombre as ciudadano_nombre, u.edad, u.municipio
            FROM expedientes e JOIN usuarios u ON e.ciudadano_id = u.id
            WHERE e.ciudadano_id = ?
        '''), (request.usuario['id'],))
    rows = cur.fetchall()

    resultado = []
    for r in rows:
        exp = dict(r)
        cur.execute(sql('SELECT * FROM pruebas WHERE expediente_id = ? ORDER BY id DESC'), (exp['id'],))
        exp['pruebas'] = [dict(p) for p in cur.fetchall()]
        cur.execute(sql('SELECT * FROM mensajes WHERE expediente_id = ? ORDER BY id ASC'), (exp['id'],))
        exp['mensajes'] = [dict(m) for m in cur.fetchall()]
        resultado.append(exp)
    conn.close()
    return jsonify(resultado)

@app.route('/api/expedientes/<int:exp_id>', methods=['PUT'])
@requiere_auth
def actualizar_expediente(exp_id):
    data = request.json or {}
    conn = get_db()
    cur = conn.cursor()
    campos = []
    valores = []
    for k in ['telefono', 'movilidad', 'materia', 'relato', 'contraparte', 'estatus', 'cita', 'acta_legal', 'firma_base64']:
        if k in data:
            campos.append(f"{k} = ?")
            valores.append(data[k])
    if campos:
        valores.append(exp_id)
        cur.execute(sql(f"UPDATE expedientes SET {', '.join(campos)} WHERE id = ?"), valores)
        conn.commit()
    conn.close()
    registrar_auditoria(request.usuario['email'], f'ACTUALIZACION_EXPEDIENTE_{exp_id}')
    return jsonify({'ok': True})

@app.route('/api/expedientes/<int:exp_id>/pruebas', methods=['POST'])
@requiere_auth
def subir_prueba(exp_id):
    if 'archivo' not in request.files:
        return jsonify({'error': 'Archivo no enviado'}), 400
    archivo = request.files['archivo']
    if not archivo.filename or not extension_valida(archivo.filename):
        return jsonify({'error': 'Formato no permitido. Use PDF, JPG, PNG, WEBM, MP4 o WAV.'}), 400

    contenido = archivo.read()
    hash_sha256 = hashlib.sha256(contenido).hexdigest()
    nombre_seguro = secure_filename(archivo.filename)
    ruta_final = os.path.join(BOVEDA_DIR, f"{exp_id}_{int(time.time())}_{nombre_seguro}")
    with open(ruta_final, 'wb') as f:
        f.write(contenido)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql('SELECT COUNT(*) as total FROM pruebas WHERE expediente_id = ?'), (exp_id,))
    fila = cur.fetchone()
    total = (fila['total'] if isinstance(fila, dict) else fila[0]) + 1

    tipo = request.form.get('tipo', 'Documento')
    prefijo = 'VID' if 'Video' in tipo else 'DOC'
    codigo = f"{prefijo}-{total:02d}"

    cur.execute(
        sql('INSERT INTO pruebas (expediente_id, codigo_prueba, tipo, nombre_archivo, ruta_guardada, hash_sha256, subido_en) VALUES (?, ?, ?, ?, ?, ?, ?)'),
        (exp_id, codigo, tipo, nombre_seguro, ruta_final, hash_sha256, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
    registrar_auditoria(request.usuario['email'], f'SUBIDA_BOVEDA_{codigo}_SHA256')
    return jsonify({'ok': True, 'hash_sha256': hash_sha256})

@app.route('/api/pruebas/<int:prueba_id>/descargar', methods=['GET'])
@requiere_auth
def descargar_prueba(prueba_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql('SELECT * FROM pruebas WHERE id = ?'), (prueba_id,))
    prueba = cur.fetchone()
    conn.close()
    if not prueba or not os.path.exists(prueba['ruta_guardada']):
        return jsonify({'error': 'Archivo no encontrado'}), 404
    registrar_auditoria(request.usuario['email'], f'DESCARGA_BOVEDA_{prueba_id}')
    return send_file(prueba['ruta_guardada'], as_attachment=True, download_name=prueba['nombre_archivo'])

@app.route('/api/expedientes/<int:exp_id>/mensajes', methods=['POST'])
@requiere_auth
def enviar_mensaje(exp_id):
    data = request.json or {}
    contenido = (data.get('contenido') or '').strip()
    if not contenido:
        return jsonify({'error': 'Mensaje vacío'}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        sql('INSERT INTO mensajes (expediente_id, autor_nombre, emisor_rol, contenido, enviado_en) VALUES (?, ?, ?, ?, ?)'),
        (exp_id, request.usuario['nombre'], request.usuario['rol'], contenido, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

if __name__ == '__main__':
    puerto = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=puerto, debug=False)
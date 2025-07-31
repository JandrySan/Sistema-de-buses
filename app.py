from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import numpy as np 
from datetime import datetime
from pymongo import MongoClient
import re
import os
import json
from bson.objectid import ObjectId
from bson.decimal128 import Decimal128
from bson.errors import InvalidId


app = Flask(__name__)
app.config['SECRET_KEY'] = 'clave_secreta_para_sesiones_123' # ¡IMPORTANTE! Usa una clave secreta más compleja en producción.

# Configuracion de LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Si el usuario no está logueado, se le redirige a esta ruta.

# Configuración de MongoDB
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
DATABASE_NAME = 'sistema_buses'

# Inicializar cliente MongoDB
client = MongoClient(MONGO_URI)
db = client[DATABASE_NAME]

# Colecciones
buses_collection = db.buses
ventas_collection = db.ventas
rutas_collection = db.rutas
usuarios_collection = db.usuarios

# Clase de Usuario para Flask-Login
class User(UserMixin):
    def __init__(self, user_id, username, role, cooperativa_id=None):
        self.id = user_id
        self.username = username
        self.role = role
        # Asegurarse de que cooperativa_id es siempre una cadena si es un ObjectId
        if isinstance(cooperativa_id, ObjectId):
            self.cooperativa_id = str(cooperativa_id)
        else:
            self.cooperativa_id = cooperativa_id

    # Método estático para cargar un usuario dado su ID
    @staticmethod
    def get(user_id):
        try:
            # Buscar el usuario en la colección de usuarios por su ID de MongoDB
            user_doc = usuarios_collection.find_one({'_id': ObjectId(user_id)})
            if user_doc:
                coop_id_from_db = user_doc.get('cooperativa_id')
                
                # Si el usuario es un 'admin' (de cooperativa), su cooperativa_id es su propio _id
                if user_doc['role'] == 'admin':
                    final_coop_id = str(user_doc['_id'])
                else:
                    # Para otros roles, usar el cooperativa_id almacenado, asegurándose de que sea una cadena si es ObjectId
                    if isinstance(coop_id_from_db, ObjectId):
                        final_coop_id = str(coop_id_from_db)
                    else:
                        final_coop_id = coop_id_from_db
                
                return User(str(user_doc['_id']), user_doc['username'], user_doc['role'], final_coop_id)
        except Exception as e:
            print(f"Error al cargar usuario por ID ({user_id}): {e}")
        return None

# Función user_loader requerida por Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


# Inicializar datos
def inicializar_datos():
    # Inicializar usuarios si no existen
    if usuarios_collection.count_documents({}) == 0:
        usuarios_iniciales = [
            {'username': 'admin_general', 'password': 'admin123', 'role': 'admin_general', 'activo': True},
            {'username': 'cliente', 'password': '123', 'role': 'usuario', 'activo': True}
        ]
        usuarios_collection.insert_many(usuarios_iniciales)
        print("Usuarios inicializados")
    
# Validaciones
def validar_texto(texto):
    return texto and texto.strip()

def validar_entero(valor):
    try:
        return int(valor)
    except (ValueError, TypeError):
        return None

def validar_cedula(cedula):
    if not isinstance(cedula, str) or len(cedula) != 10 or not cedula.isdigit():
        return False

    provincia = int(cedula[0:2])
    if provincia < 1 or provincia > 24: # Provincias válidas de 1 a 24
        return False

    tercer_digito = int(cedula[2])
    if tercer_digito >= 6: # El tercer dígito debe ser menor a 6 (0-5)
        return False

    coeficientes = [2, 1, 2, 1, 2, 1, 2, 1, 2]
    total = 0
    for i in range(9):
        digito = int(cedula[i]) * coeficientes[i]
        if digito >= 10:
            digito -= 9
        total += digito

    ultimo_digito = int(cedula[9])
    
    # Calcular el dígito verificador
    residuo = total % 10
    digito_verificador = 0 if residuo == 0 else 10 - residuo

    return digito_verificador == ultimo_digito

# Decoradores de roles
def admin_general_required(f):
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin_general':
            flash('Se requieren permisos de administrador general')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__ 
    return decorated_function

def admin_required(f):
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin': 
            flash('Se requieren permisos de administrador')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__ 
    return decorated_function

def empleado_required(f):
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'empleado':
            flash('Se requieren permisos de empleado')
            return redirect(url_for('index')) 
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__ 
    return decorated_function

def usuario_required(f):
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'usuario':
            flash('No tienes acceso a esto')
            return redirect(url_for('index')) 
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__ 
    return decorated_function

###################
#Login y registro #
###################

# Llama al index para mostrar
@app.route('/')
def index():
    if current_user.is_authenticated:
        # Redirección basada en el rol del usuario autenticado
        if current_user.role == 'admin_general':
            return redirect(url_for('dashboard_admin_general'))
        elif current_user.role == 'admin':
            return redirect(url_for('dashboard_admin'))
        elif current_user.role == 'empleado':
            return redirect(url_for('dashboard_empleado'))
        elif current_user.role == 'usuario':
            return redirect(url_for('dashboard_usuario'))
        else:
            return redirect(url_for('index')) 
    return redirect(url_for('login')) # Si no está logueado, va a la pagina de login

# Inicio de sesion
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Si el usuario ya está logueado, redirigirlo a su dashboard
    if current_user.is_authenticated:
        if current_user.role == 'admin_general':
            return redirect(url_for('dashboard_admin_general'))
        elif current_user.role == 'admin':
            return redirect(url_for('dashboard_admin'))
        elif current_user.role == 'empleado':
            return redirect(url_for('dashboard_empleado'))
        elif current_user.role == 'usuario':
            return redirect(url_for('dashboard_usuario'))
        else:
            return redirect(url_for('index'))

    if request.method == 'POST':
        usuario_username = request.form['username'].strip()
        password = request.form['password'].strip()

        usuario_doc = usuarios_collection.find_one({'username': usuario_username})

        if usuario_doc and usuario_doc['password'] == password: # Considera usar generate_password_hash y check_password_hash para seguridad
            if not usuario_doc.get('activo', True):
                flash('Usuario desactivado. Por favor, contacte al administrador.')
                return render_template('login.html')

            # Crear un objeto User y loguearlo con Flask-Login
            user_id_str = str(usuario_doc['_id'])
            
            #Determina cooperativa_id_for_user basada en el rol
            cooperativa_id_for_user = None
            if usuario_doc['role'] == 'admin':
                # Para un admin de cooperativa, su cooperativa_id es su propio _id
                cooperativa_id_for_user = user_id_str
            elif usuario_doc['role'] == 'empleado':
                # Para un empleado, su cooperativa_id debe venir del documento de la base de datos
                cooperativa_id_for_user = usuario_doc.get('cooperativa_id')
                if isinstance(cooperativa_id_for_user, ObjectId):
                    cooperativa_id_for_user = str(cooperativa_id_for_user)

            user = User(user_id_str, usuario_doc['username'], usuario_doc['role'], cooperativa_id_for_user)
            login_user(user) # Esto establece la sesión del usuario con Flask-Login

            flash(f'¡Bienvenido, {usuario_doc["username"]}!')

            # Redirección basada en el rol
            rol = usuario_doc['role']
            if rol == 'admin_general':
                return redirect(url_for('dashboard_admin_general'))
            elif rol == 'admin':
                return redirect(url_for('dashboard_admin'))
            elif rol == 'empleado':
                return redirect(url_for('dashboard_empleado'))
            elif rol == 'usuario':
                return redirect(url_for('dashboard_usuario'))
            else:
                return redirect(url_for('index'))

        else:
            flash('Usuario o contraseña incorrectos.')
    
    return render_template('login.html')

# Registro
@app.route('/registro_usuario', methods=['GET', 'POST'])
def registro_usuario():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()

        if not username or not password:
            flash('Todos los campos son obligatorios')
            return render_template('registro_usuario.html')

        if usuarios_collection.find_one({'username': username}):
            flash('Este usuario ya existe')
            return render_template('registro_usuario.html')

        nuevo_usuario = {
            'username': username,
            'password': password,
            'role': 'usuario',
            'activo': True 
        }
        usuarios_collection.insert_one(nuevo_usuario)
        flash('Cuenta creada exitosamente. Ahora puedes iniciar sesión.')
        return redirect(url_for('login'))

    return render_template('registro_usuario.html')

# Cerrar Sesion
@app.route('/logout')
@login_required 
def logout():
    logout_user() 
    flash('Sesión cerrada.')
    return redirect(url_for('login'))

####################################
#--------- Rutas por rol ----------#
####################################

###################
#   Admin general  #
###################

#---- Dashboard
@app.route('/dashboard_admin_general')
@admin_general_required 
def dashboard_admin_general():
    total_usuarios = usuarios_collection.count_documents({})
    total_rutas = rutas_collection.count_documents({})
    
    stats = {
        'username': total_usuarios,
        'rutas': total_rutas
    }

    return render_template('dashboard_admin_general.html', stats=stats)

#Funcion de Registrar admin
@app.route('/registrar_admin', methods=['GET', 'POST'])
@admin_general_required 
def registrar_admin():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()

        if not username or not password:
            flash('Todos los campos son obligatorios')
            return render_template('registrar_admin.html')

        if usuarios_collection.find_one({'username': username}):
            flash('Este nombre de usuario ya existe')
            return render_template('registrar_admin.html')

        nuevo_admin = {
            'username': username,
            'password': password, 
            'role': 'admin',
            'activo': True 
        }
        usuarios_collection.insert_one(nuevo_admin)
        flash('Administrador de cooperativa registrado con éxito')
        return redirect(url_for('listar_cooperativas'))
    return render_template('registrar_admin.html')

#ver Usuarios
@app.route('/usuarios')
@admin_general_required 
def mostrar_usuarios():
    usuarios = list(usuarios_collection.find())
    return render_template('usuarios.html', usuarios=usuarios)

#Administrar Cooperativas
@app.route('/gestionar_cooperativas')
@admin_general_required
def gestionar_cooperativas():
    return render_template('gestionar_cooperativas.html')

#Listar cooperativas
@app.route('/cooperativas')
@admin_general_required
def listar_cooperativas():
    cooperativas = list(usuarios_collection.find({'role': 'admin'}))
    return render_template('cooperativas.html', cooperativas=cooperativas)

#Desactivar usuario
@app.route('/desactivar_usuario/<usuario_id>')
@admin_general_required
def desactivar_usuario(usuario_id):
    usuarios_collection.update_one({'_id': ObjectId(usuario_id)}, {'$set': {'activo': False}})
    flash('Usuario desactivado')
    return redirect(url_for('mostrar_usuarios'))

#Activar Usuario
@app.route('/activar_usuario/<usuario_id>')
@admin_general_required
def activar_usuario(usuario_id):
    usuarios_collection.update_one({'_id': ObjectId(usuario_id)}, {'$set': {'activo': True}})
    flash('Usuario activado')
    return redirect(url_for('mostrar_usuarios'))

#Eliminar Usuario
@app.route('/eliminar_usuario/<usuario_id>')
@admin_general_required
def eliminar_usuario(usuario_id):
    usuarios_collection.delete_one({'_id': ObjectId(usuario_id)})
    flash('Usuario eliminado definitivamente')
    return redirect(url_for('mostrar_usuarios'))

#Crear Cooperativas

@app.route('/agregar_cooperativa', methods=['POST'])
@admin_general_required
def agregar_cooperativa():
    nombre = request.form.get('nombre').strip()
    username = request.form.get('username').strip()
    password = request.form.get('password').strip()

    if not nombre or not username or not password:
        flash('Todos los campos son obligatorios')
        return redirect(url_for('listar_cooperativas'))

    if usuarios_collection.find_one({'username': username}):
        flash('El usuario ya existe')
        return redirect(url_for('listar_cooperativas'))

    nueva_cooperativa = {
        'nombre': nombre,
        'username': username,
        'password': password,
        'role': 'admin',
        'activo': True
    }
    usuarios_collection.insert_one(nueva_cooperativa)
    flash('Cooperativa agregada con éxito')
    return redirect(url_for('listar_cooperativas'))

##########################
#     Admin Cooperativa   #
##########################

#Dashboard admin
@app.route('/dashboard_admin')
@admin_required
def dashboard_admin():
    cooperativa_id = current_user.cooperativa_id
    
    if not cooperativa_id:
        flash('No se pudo identificar la cooperativa para el dashboard.')
        return redirect(url_for('index')) # Redirige a una página segura

    stats = {
        'total_buses': buses_collection.count_documents({'cooperativa_id': ObjectId(cooperativa_id)}),
        'total_ventas': ventas_collection.count_documents({'cooperativa_id': ObjectId(cooperativa_id)}),
        'total_rutas': rutas_collection.count_documents({'cooperativa_id': ObjectId(cooperativa_id)}),
        'ingresos_totales': sum(v['precio'] for v in ventas_collection.find({'estado': 'vendido', 'cooperativa_id': ObjectId(cooperativa_id)})),
        'reservaciones': ventas_collection.count_documents({'estado': 'reservado', 'cooperativa_id': ObjectId(cooperativa_id)})
    }
    return render_template('dashboard_admin.html', stats=stats)


#Registrar Empleado
@app.route('/registrar_empleado', methods=['GET', 'POST'])
@admin_required
def registrar_empleado():
    if request.method == 'POST':
        nombre = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = 'empleado'
        cooperativa_id = current_user.cooperativa_id

        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            flash('Formato de correo electrónico inválido.', 'danger')
            return redirect(url_for('registrar_empleado'))

        # 2. Validar que el correo no esté registrado
        if usuarios_collection.find_one({'email': email}):
            flash('Este correo electrónico ya está registrado.', 'danger')
            return redirect(url_for('registrar_empleado'))
        
        # 3. Validar otros campos (ej. que no estén vacíos)
        if not nombre or not password or not email:
            flash('Todos los campos son obligatorios.', 'danger')
            return redirect(url_for('registrar_empleado'))

        if not cooperativa_id:
            flash('No se pudo identificar la cooperativa para el registro.', 'danger')
            return redirect(url_for('dashboard_admin'))
        
        # Guardar en MongoDB
        usuarios_collection.insert_one({
                'username': nombre,
                'email': email,
                'password': password,
                'role': role,
                'cooperativa_id': ObjectId(cooperativa_id),
                'activo': True # O el estado inicial que desees
            })
        flash('Empleado registrado exitosamente', 'success')
        return redirect(url_for('ver_empleados'))

    return render_template('registro_empleado.html')

#Ver empleados
@app.route('/ver_empleados')
@admin_required
def ver_empleados():
    cooperativa_id = current_user.cooperativa_id
    if not cooperativa_id:
        flash('No se pudo identificar la cooperativa.', 'danger')
        return redirect(url_for('ver_empleados'))
     
    empleados = list(usuarios_collection.find({
        'role': 'empleado',
        'cooperativa_id': ObjectId(cooperativa_id)
    }))

    return render_template('ver_empleados.html', empleados=empleados)

#Eliminar empleados
@app.route('/eliminar_empleado/<empleados_id>', methods=['POST', 'GET'])
@admin_required
def eliminar_empleado(empleados_id):
    try:
        # Intenta convertir el ID a ObjectId
        obj_id = ObjectId(empleados_id)
    except Exception:
        flash('ID de empleado inválido.', 'danger')
        return redirect(url_for('ver_empleados'))

    # Asegúrate de que el empleado pertenece a la cooperativa del admin actual
    cooperativa_id = current_user.cooperativa_id
    if not cooperativa_id:
        flash('No se pudo identificar la cooperativa para la eliminación.', 'danger')
        return redirect(url_for('ver_empleados'))

    # Eliminar el empleado de la colección 'usuarios'
    result = usuarios_collection.delete_one({
        '_id': obj_id,
        'role': 'empleado',
        'cooperativa_id': ObjectId(cooperativa_id)
    })

    if result.deleted_count == 1:
        flash('Empleado eliminado exitosamente.', 'success')
    else:
        flash('No se encontró el empleado o no tienes permiso para eliminarlo.', 'warning')

    return redirect(url_for('ver_empleados'))

#################
#    Empleado   #
#################

# Dashboard empleado
@app.route('/dashboard_empleado')
@empleado_required
def dashboard_empleado():
    vendedor = current_user.username
    ventas = list(ventas_collection.find({'vendedor': vendedor}))

    cooperativa_id = current_user.cooperativa_id
    total_rutas = rutas_collection.count_documents({'cooperativa_id': ObjectId(cooperativa_id)})

    stats = {
        'ventas_realizadas': len(ventas),
        'ingresos_generados': sum(v.get('precio', 0) for v in ventas if v.get('estado') == 'vendido'),
        'total_rutas': total_rutas
    }

    return render_template('dashboard_empleado.html', stats=stats)

################
#    Usuario   #
################

# Dashboard usuario
@app.route('/dashboard_usuario')
@usuario_required 
def dashboard_usuario():
    # Estadísticas para el usuario
    username = current_user.username # El username del usuario logueado
    
    # Total de rutas disponibles (para todos los usuarios)
    total_rutas_disponibles = rutas_collection.count_documents({})

    # Boletos comprados por el usuario
    boletos_comprados_docs = list(ventas_collection.find({'cedula': username, 'estado': 'vendido'})) # Asumiendo que 'cedula' del comprador es el username
    boletos_comprados = len(boletos_comprados_docs)

    # Reservaciones activas del usuario
    reservaciones_activas_docs = list(ventas_collection.find({'cedula': username, 'estado': 'reservado'})) # Asumiendo que 'cedula' del comprador es el username
    reservaciones_activas = len(reservaciones_activas_docs)

    # Gasto total del usuario
    gasto_total = sum(float(str(v['precio'])) if isinstance(v['precio'], Decimal128) else float(v['precio']) for v in boletos_comprados_docs)

    stats = {
        'total_rutas_disponibles': total_rutas_disponibles,
        'boletos_comprados': boletos_comprados,
        'reservaciones_activas': reservaciones_activas,
        'gasto_total': gasto_total
    }

    return render_template('dashboard_usuario.html', stats=stats)

#Ver rutas
@app.route('/ver_rutas')
@usuario_required
def ver_rutas():
    rutas_disponibles = list(rutas_collection.find())
    for ruta in rutas_disponibles:
        coop_id = ruta.get('cooperativa_id')
        print(f"DEBUG: Ruta: {ruta.get('origen')} -> {ruta.get('destino')}, ID de cooperativa: {coop_id}")

        if coop_id:
            try:
                # Asegurarse de que coop_id es un ObjectId válido
                coop = usuarios_collection.find_one({'_id': ObjectId(coop_id)})
                if coop:
                    # Preferir 'nombre', si no existe, usar 'username' como fallback
                    ruta['nombre_cooperativa'] = coop.get('nombre', coop.get('username', 'Cooperativa sin nombre'))
                else:
                    ruta['nombre_cooperativa'] = 'Cooperativa no encontrada (ID no existe)'
            except Exception as e:
                ruta['nombre_cooperativa'] = 'Error al procesar Cooperativa ID'
        else:
            ruta['nombre_cooperativa'] = 'Cooperativa no definida en ruta'
        
        # Asegurarse de que precio_base es un float para la plantilla
        precio_base_val = ruta.get('precio_base', 0.0)
        if isinstance(precio_base_val, Decimal128):
            ruta['precio_base'] = float(str(precio_base_val))
        else:
            ruta['precio_base'] = float(precio_base_val)

    return render_template('ver_rutas.html', rutas=rutas_disponibles)

# Historial de compras del usuario
@app.route('/historial_compras')
@usuario_required
def historial_compras():
    username_del_cliente = current_user.username
    compras_usuario = list(ventas_collection.find({'vendedor': username_del_cliente, 'estado': 'vendido'}))
    for compra in compras_usuario:
        print(f" - Compra ID: {compra.get('_id')}, Precio: {compra.get('precio')}, Estado: {compra.get('estado')}")
        for compra in compras_usuario:
            if 'precio' in compra and isinstance(compra['precio'], Decimal128):
                compra['precio'] = float(str(compra['precio']))
            compra['_id'] = str(compra['_id'])

    return render_template('historial_compras.html', compras=compras_usuario)

#################
#----Sistema----#
#################

#####################
#    Estadisticas   #
##################### 

#Dashboard de reportes
@app.route('/reportes')
@admin_required
def reportes():
    cooperativa_id = current_user.cooperativa_id
    if not cooperativa_id:
        flash('No se pudo identificar la cooperativa para los reportes.')
        return redirect(url_for('dashboard_admin'))

    # Obtener todas las ventas de la cooperativa del usuario logueado
    todas_ventas = list(ventas_collection.find({'cooperativa_id': ObjectId(cooperativa_id)}))
    
    ventas_por_usuario = {}
    ventas_por_ruta = {}

    for v in todas_ventas:
        usuario = v.get('vendedor', 'Desconocido') 
        ruta = f"{v.get('origen', 'N/A')} -> {v.get('destino', 'N/A')}"
        
        if usuario not in ventas_por_usuario:
            ventas_por_usuario[usuario] = {'cantidad': 0, 'ingresos': 0}
        if ruta not in ventas_por_ruta:
            ventas_por_ruta[ruta] = {'cantidad': 0, 'ingresos': 0}

        ventas_por_usuario[usuario]['cantidad'] += 1
        ventas_por_ruta[ruta]['cantidad'] += 1

        if v.get('estado') == 'vendido':
            precio_val = v.get('precio', 0)
            if isinstance(precio_val, Decimal128):
                precio_val = float(str(precio_val))
            ventas_por_usuario[usuario]['ingresos'] += precio_val
            ventas_por_ruta[ruta]['ingresos'] += precio_val

    # Estadísticas con numpy
    ventas_vendidas = [v for v in todas_ventas if v.get('estado') == 'vendido']
    precios = np.array([float(str(p)) if isinstance(p, Decimal128) else p for p in [v.get('precio', 0) for v in ventas_vendidas]])
    
    estadisticas = {
        'total_ventas': len(todas_ventas),
        'total_ingresos': float(precios.sum() if precios.size > 0 else 0),
        'promedio_precio': precios.mean() if precios.size > 0 else 0,
        'precio_maximo': precios.max() if precios.size > 0 else 0,
        'precio_minimo': precios.min() if precios.size > 0 else 0
    }

    return render_template('reportes.html',ventas_por_usuario=ventas_por_usuario, ventas_por_ruta=ventas_por_ruta,estadisticas=estadisticas)

#Mostrar las ventas
@app.route('/ventas')
@admin_required
def mostrar_ventas():
    cooperativa_id = current_user.cooperativa_id
    if not cooperativa_id:
        flash('No se pudo identificar la cooperativa')
        return redirect(url_for('dashboard_admin'))

    ventas = list(ventas_collection.find({'cooperativa_id': ObjectId(cooperativa_id)}))
    return render_template('ventas.html', ventas=ventas)

#Mostrar reservas
@app.route('/mis_reservas')
@usuario_required
def mis_reservas():
    id_del_usuario_actual = current_user.id
    
    # Busca tanto reservas ('reservado') como boletos comprados ('vendido') para el usuario logueado
    # Filtrar por 'user_id' que es el _id del usuario en la colección 'usuarios'
    reservas_y_compras_usuario = list(ventas_collection.find({
        'user_id': ObjectId(id_del_usuario_actual),
        'estado': 'reservado'
    }).sort('fecha', -1)) # Ordenar por fecha descendente

    # Procesar cada documento para asegurar el formato de precio y añadir nombre de cooperativa
    for venta in reservas_y_compras_usuario:
        if 'precio' in venta and isinstance(venta['precio'], Decimal128):
            venta['precio'] = float(str(venta['precio']))
        elif 'precio' in venta and not isinstance(venta['precio'], (float, int)):
            try:
                venta['precio'] = float(venta['precio'])
            except ValueError:
                venta['precio'] = 0.0 # Valor por defecto si no se puede convertir
        
        venta['_id'] = str(venta['_id']) # Convertir ObjectId a string para la plantilla

        # Obtener el nombre de la cooperativa si existe
        cooperativa_id = venta.get('cooperativa_id')
        if cooperativa_id:
            try:
                # Asegurarse de que cooperativa_id es un ObjectId válido
                coop = usuarios_collection.find_one({'_id': ObjectId(cooperativa_id), 'role': 'admin'})
                if coop:
                    venta['nombre_cooperativa'] = coop.get('nombre', coop.get('username', 'Cooperativa Desconocida'))
                else:
                    venta['nombre_cooperativa'] = 'Cooperativa no encontrada'
            except Exception as e:
                venta['nombre_cooperativa'] = 'Error al cargar Cooperativa'
        else:
            venta['nombre_cooperativa'] = 'N/A' # Si no hay cooperativa_id en la venta

    return render_template('reservados.html', reservas=reservas_y_compras_usuario, role='usuario')


@app.route('/reservas_cooperativa')
@login_required 
def reservas_cooperativa():
    # Asegúrate de que solo admins y empleados puedan acceder a esta ruta
    if current_user.role not in ['admin', 'empleado']:
        flash('No tienes permiso para ver esta sección.', 'danger')
        if current_user.role == 'usuario':
            return redirect(url_for('mis_reservas')) # O a su dashboard principal
        return redirect(url_for('login')) # O a una página de error

    cooperativa_id = current_user.cooperativa_id
    if not cooperativa_id:
        flash('No se pudo identificar la cooperativa de tu cuenta.', 'danger')
        if current_user.role == 'admin':
            return redirect(url_for('dashboard_admin'))
        elif current_user.role == 'empleado':
            return redirect(url_for('dashboard_empleado'))
        return redirect(url_for('login'))


    reservas = list(ventas_collection.find({
        'cooperativa_id': ObjectId(cooperativa_id),
        'estado': 'reservado'
    }).sort('fecha', -1)) 

    for venta in reservas:
        if 'precio' in venta and isinstance(venta['precio'], Decimal128):
            venta['precio'] = float(str(venta['precio']))
        elif 'precio' in venta and not isinstance(venta['precio'], (float, int)):
            try:
                venta['precio'] = float(venta['precio'])
            except ValueError:
                venta['precio'] = 0.0
        
        venta['_id'] = str(venta['_id']) 
        
        # Obtener el nombre de la cooperativa
        admin_coop_doc = usuarios_collection.find_one({'_id': ObjectId(cooperativa_id), 'role': 'admin'})
        if admin_coop_doc:
            venta['nombre_cooperativa'] = admin_coop_doc.get('nombre', admin_coop_doc.get('username', 'Tu Cooperativa'))
        else:
            venta['nombre_cooperativa'] = 'Cooperativa No Disponible'

    return render_template('reservados.html', reservas=reservas, role=current_user.role)


#Confirmar reservas
@app.route('/confirmar_reserva/<venta_id>', methods=['POST'])
@login_required 
def confirmar_reserva(venta_id):
    try:
        filter_query = {'_id': ObjectId(venta_id)}
        if current_user.is_authenticated and current_user.role in ['admin', 'empleado'] and current_user.cooperativa_id:
            filter_query['cooperativa_id'] = ObjectId(current_user.cooperativa_id)

        result = ventas_collection.update_one(
            filter_query,
            {'$set': {'estado': 'vendido'}}
        )
        if result.modified_count > 0:
            flash('Reserva confirmada como venta')
        else:
            flash('Reserva no encontrada o no tienes permiso para confirmarla.')
    except Exception as e:
        flash(f'Error al confirmar la reserva: {e}')
    
    return redirect(url_for('mis_reservas'))

@app.route('/confirmar_reserva_cooperativa/<venta_id>', methods=['POST'])
@login_required # Puede ser admin o empleado
def confirmar_reserva_cooperativa(venta_id):
    if current_user.role not in ['admin', 'empleado']:
        flash('No tienes permiso para realizar esta acción.', 'danger')
        return redirect(url_for('reservas_cooperativa'))

    cooperativa_id = current_user.cooperativa_id
    try:
        venta = ventas_collection.find_one({'_id': ObjectId(venta_id), 'cooperativa_id': ObjectId(cooperativa_id)})
        
        if venta and venta['estado'] == 'reservado':
            # Ambos, admin y empleado, pueden confirmar (ejemplo)
            ventas_collection.update_one({'_id': ObjectId(venta_id)}, {'$set': {'estado': 'vendido', 'fecha_venta': datetime.now()}})
            flash('Reserva confirmada y marcada como vendida exitosamente.', 'success')
        else:
            flash('Reserva no encontrada o no está en estado "reservado".', 'danger')
    except InvalidId:
        flash('ID de reserva inválido.', 'danger')
    except Exception as e:
        flash(f'Error al confirmar la reserva: {e}', 'danger')
    return redirect(url_for('reservas_cooperativa'))



#Cancelar Reservas
@app.route('/cancelar_reserva/<venta_id>', methods=['GET'])
@login_required 
def cancelar_reserva(venta_id):
    try:
        filter_query = {'_id': ObjectId(venta_id)}
        if current_user.is_authenticated:
            if current_user.role == 'usuario':
                pass 
            elif current_user.role in ['admin', 'empleado'] and current_user.cooperativa_id:
                filter_query['cooperativa_id'] = ObjectId(current_user.cooperativa_id)
            else:
                flash('No tienes permisos para cancelar esta reserva.', 'danger')
                return redirect(url_for('mostrar_reservados'))
        else:
            flash('Debes iniciar sesión para cancelar una reserva.', 'danger')
            return redirect(url_for('login'))
        
        result = ventas_collection.delete_one(filter_query)
        if result.deleted_count > 0:
            flash('Reserva cancelada exitosamente.', 'success')
        else:
            flash('Reserva no encontrada, ya cancelada, o no tienes permiso para cancelarla.', 'warning')
    except Exception as e:
        flash(f'Error al cancelar la reserva: {e}', 'danger')
    
    return redirect(url_for('mis_reservas'))


@app.route('/cancelar_reserva_cooperativa/<venta_id>', methods=['POST'])
@login_required # Puede ser admin o empleado
def cancelar_reserva_cooperativa(venta_id):
    if current_user.role not in ['admin', 'empleado']:
        flash('No tienes permiso para realizar esta acción.', 'danger')
        return redirect(url_for('reservas_cooperativa')) # Redirige a la vista de cooperativa

    cooperativa_id = current_user.cooperativa_id
    try:
        venta = ventas_collection.find_one({'_id': ObjectId(venta_id), 'cooperativa_id': ObjectId(cooperativa_id)})
        
        if venta and venta['estado'] == 'reservado':
            # Lógica de permisos más fina: solo el admin puede cancelar?
            if current_user.role == 'admin':
                ventas_collection.update_one({'_id': ObjectId(venta_id)}, {'$set': {'estado': 'cancelado', 'fecha_cancelacion': datetime.now()}})
                flash('Reserva cancelada exitosamente por el administrador.', 'success')
            else: # Empleado no puede cancelar (ejemplo de restricción)
                flash('Solo un administrador puede cancelar reservas.', 'danger')
        else:
            flash('Reserva no encontrada o no está en estado "reservado".', 'danger')
    except InvalidId:
        flash('ID de reserva inválido.', 'danger')
    except Exception as e:
        flash(f'Error al cancelar la reserva: {e}', 'danger')
    return redirect(url_for('reservas_cooperativa'))


#Pagar reservas
@app.route('/pagar_reserva/<venta_id>', methods=['POST'])
@usuario_required
def pagar_reserva(venta_id):
    try:
        venta = ventas_collection.find_one({'_id': ObjectId(venta_id), 'user_id': ObjectId(current_user.id), 'estado': 'reservado'})
        if venta:
            ventas_collection.update_one({'_id': ObjectId(venta_id)}, {'$set': {'estado': 'vendido', 'fecha_venta': datetime.now()}})
            flash('Reserva pagada y convertida en venta exitosamente.', 'success')
        else:
            flash('Reserva no encontrada o no puedes realizar esta acción (ya pagada o no te pertenece).', 'danger')
    except InvalidId:
        flash('ID de reserva inválido.', 'danger')
    except Exception as e:
        flash(f'Error al procesar el pago: {e}', 'danger')
    return redirect(url_for('mis_reservas'))

#Ver asientos ocupados
@app.route('/api/asientos_ocupados/<ruta_id>')
@login_required
def asientos_ocupados(ruta_id):
    try:
        ruta_sel = rutas_collection.find_one({'_id': ObjectId(ruta_id)})
        if not ruta_sel:
            return jsonify({'error': 'Ruta no encontrada'}), 404

        ventas = ventas_collection.find({
            'ruta_id': ObjectId(ruta_id),
            'fecha': ruta_sel.get('fecha', '') 
        })

        ocupados = []
        for v in ventas:
            if 'asiento' in v:
                ocupados.append({'numero': v['asiento'], 'estado': v.get('estado', 'vendido')})

        total_asientos_ruta = ruta_sel.get('asientos_disponibles', 40) 
        if 'bus_id' in ruta_sel:
            bus = buses_collection.find_one({'_id': ruta_sel['bus_id']})
            if bus:
                total_asientos_ruta = bus.get('asientos', total_asientos_ruta) 

        return jsonify({
            'asientos_ocupados': ocupados,
            'total_asientos': total_asientos_ruta
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

#Venta de boletos
@app.route('/venta_boletos', methods=['GET', 'POST'])
@login_required 
def venta_boletos():
    rutas = list(rutas_collection.find())
    ruta_id = request.args.get('ruta_id') if request.method == 'GET' else request.form.get('ruta_id')
    ruta_sel = rutas_collection.find_one({'_id': ObjectId(ruta_id)}) if ruta_id else None

    bus = None
    if ruta_sel and 'bus_id' in ruta_sel:
        bus = buses_collection.find_one({'_id': ruta_sel['bus_id']})

    if request.method == 'POST':
        if not ruta_sel:
            flash('Ruta no encontrada')
            return redirect(url_for('venta_boletos'))

        cedula = request.form['cedula']
        nombre = request.form['nombre']
        apellido = request.form['apellido']
        estado = request.form.get('estado', 'vendido').lower()

        asientos_str = request.form.get('asientos_seleccionados', '')
        asientos = [int(a) for a in asientos_str.split(',') if a.strip().isdigit()]

        if not asientos:
            flash("Debe seleccionar al menos un asiento.")
            return redirect(url_for('venta_boletos', ruta_id=ruta_id))
        
        if not validar_cedula(cedula):
            flash('Cédula del comprador inválida. Por favor, verifique el número.')
            return redirect(url_for('venta_boletos', ruta_id=ruta_id))
        
        if current_user.is_authenticated:
            id_del_usuario_logueado = current_user.id # Este es el _id de tu objeto User en Flask-Login
        else:
            id_del_usuario_logueado = None

        ventas_actuales = list(ventas_collection.find({
            'ruta_id': ObjectId(ruta_id),
            'fecha': ruta_sel.get('fecha', '') 
        }))
        asientos_ocupados = [int(v['asiento']) for v in ventas_actuales]
        max_asientos = bus['asientos'] if bus else ruta_sel.get('asientos_disponibles', 40)

        cooperativa_id_para_venta = None
        if 'cooperativa_id' in ruta_sel and ruta_sel['cooperativa_id'] is not None:
            raw_cooperativa_id_ruta = ruta_sel['cooperativa_id']
                # Intentar convertir a ObjectId. Si falla, significa que el ID no es válido.
            if isinstance(raw_cooperativa_id_ruta, str):
                cooperativa_id_para_venta = ObjectId(raw_cooperativa_id_ruta)
            elif isinstance(raw_cooperativa_id_ruta, ObjectId):
                cooperativa_id_para_venta = raw_cooperativa_id_ruta

        for asiento in asientos:
            if asiento in asientos_ocupados or asiento < 1 or asiento > max_asientos:
                flash(f"Asiento {asiento} inválido o ya ocupado.")
                return redirect(url_for('venta_boletos', ruta_id=ruta_id))

        precio_unitario = float(ruta_sel['precio_base'])

        for asiento in asientos:
            nueva_venta = {
                'ruta_id': ObjectId(ruta_id),
                'vendedor': current_user.username,
                'cedula': cedula,
                'nombre': nombre,
                'apellido': apellido,
                'precio': precio_unitario,
                'origen': ruta_sel['origen'],
                'destino': ruta_sel['destino'],
                'fecha': ruta_sel['fecha'],
                'hora': ruta_sel['hora'],
                'estado': estado,
                'asiento': asiento,
                'fecha_venta': datetime.now().strftime('%d-%m-%Y %H:%M'),
                'cooperativa_id': ObjectId(current_user.cooperativa_id) if current_user.cooperativa_id else cooperativa_id_para_venta,
                'user_id': ObjectId(id_del_usuario_logueado) if id_del_usuario_logueado else None
            }
            ventas_collection.insert_one(nueva_venta)

        flash(f'Boletos registrados correctamente ({len(asientos)} asiento(s)).')
        return redirect(url_for('venta_boletos', ruta_id=ruta_id))

    # Obtener los asientos ocupados para la vista GET
    asientos_ocupados_para_vista = []
    max_asientos = bus['asientos'] if bus else (ruta_sel.get('asientos_disponibles', 40) if ruta_sel else 40)
    if ruta_sel:
        ventas_para_vista = list(ventas_collection.find({
            'ruta_id': ObjectId(ruta_id),
            'fecha': ruta_sel.get('fecha', '') 
        }))
        asientos_ocupados_para_vista = [
            {'asiento': int(v['asiento']), 'estado': v['estado']}
            for v in ventas_para_vista
        ]
    return render_template('venta_boletos.html',rutas=rutas,ruta_sel=ruta_sel,asientos_ocupados=asientos_ocupados_para_vista,max_asientos=max_asientos)

#########################
#    Sistema de buses   #
#########################

#Registro de Buses
@app.route('/registrar_bus', methods=['GET', 'POST'])
@admin_required
def registrar_bus():
    if request.method == 'POST':
        cedula = request.form['cedula']
        nombres = validar_texto(request.form['nombres'])
        apellidos = validar_texto(request.form['apellidos'])
        placa = validar_texto(request.form['placa'])
        marca = validar_texto(request.form['marca'])
        combustible = validar_texto(request.form['combustible'])
        color = validar_texto(request.form['color'])
        motor = validar_texto(request.form['motor'])
        ruedas = validar_entero(request.form['ruedas'])
        pasajeros = validar_entero(request.form['pasajeros'])
        asientos = validar_entero(request.form['asientos'])

        if not all([cedula, nombres, apellidos, placa, marca, combustible, color, motor, ruedas, pasajeros, asientos]):
            flash('Todos los campos son obligatorios')
            return render_template('registrar_bus.html')
        
        if not validar_cedula(cedula):
            flash('Cédula del conductor inválida. Por favor, verifique el número.')
            return render_template('registrar_bus.html')

        # Verificar si ya existe un bus con esa placa dentro de la misma cooperativa
        if buses_collection.find_one({'placa': placa, 'cooperativa_id': ObjectId(current_user.cooperativa_id)}):
            flash('Ya existe un bus con esa placa en tu cooperativa.')
            return render_template('registrar_bus.html')

        cooperativa_id = current_user.cooperativa_id
        if not cooperativa_id:
            flash('No se pudo identificar la cooperativa para registrar el bus.')
            return redirect(url_for('dashboard_admin'))

        nuevo_bus = {
            'cedula': cedula,
            'nombres': nombres,
            'apellidos': apellidos,
            'placa': placa,
            'marca': marca,
            'combustible': combustible,
            'color': color,
            'motor': motor,
            'ruedas': ruedas,
            'pasajeros': pasajeros,
            'asientos': asientos,
            'fecha_registro': datetime.now().strftime('%d-%m-%Y %H:%M'),
            'cooperativa_id': ObjectId(cooperativa_id)
        }
        
        buses_collection.insert_one(nuevo_bus)
        flash('Bus registrado exitosamente')
        return redirect(url_for('mostrar_buses'))
    return render_template('registrar_bus.html')

#Ver buses
@app.route('/buses')
@admin_required
def mostrar_buses():
    cooperativa_id = current_user.cooperativa_id
    if not cooperativa_id:
        flash('No se pudo identificar la cooperativa')
        return redirect(url_for('dashboard_admin'))

    buses = list(buses_collection.find({'cooperativa_id': ObjectId(cooperativa_id)}))
    return render_template('buses.html', buses=buses)


#Crear ruta
def serializar_ruta(ruta):
    # Asegúrate de que los IDs sean strings para el frontend
    ruta['_id'] = str(ruta['_id'])
    if 'bus_id' in ruta:
        ruta['bus_id'] = str(ruta['bus_id'])
    if 'cooperativa_id' in ruta:
        ruta['cooperativa_id'] = str(ruta['cooperativa_id'])
    
    # Convertir Decimal128 a float para precio_base
    if 'precio_base' in ruta and isinstance(ruta['precio_base'], Decimal128):
        ruta['precio_base'] = float(str(ruta['precio_base']))
    print(f"DEBUG (serializar_ruta): Ruta serializada con precio_base: {ruta.get('precio_base')} (tipo: {type(ruta.get('precio_base'))})")
    
    # Convertir Decimal128 a int para asientos_disponibles
    if 'asientos_disponibles' in ruta and isinstance(ruta['asientos_disponibles'], Decimal128):
        ruta['asientos_disponibles'] = int(str(ruta['asientos_disponibles']))
    return ruta

@app.route('/agregar_ruta', methods=['GET', 'POST'])
@admin_required
def agregar_ruta():
    cooperativa_id = current_user.cooperativa_id
    if not cooperativa_id:
        flash('No se pudo identificar la cooperativa para agregar la ruta.')
        return redirect(url_for('dashboard_admin'))
    
    # Solo muestra buses de la cooperativa del admin logueado
    buses = list(buses_collection.find({'cooperativa_id': ObjectId(cooperativa_id)}))

    if request.method == 'POST':
        origen = request.form['origen'].strip()
        destino = request.form['destino'].strip()
        fecha = request.form['fecha'].strip()
        hora = request.form['hora'].strip()
        precio_base = float(request.form['precio_base'])
        bus_id = request.form.get('bus_id')

        # Buscar bus para tomar su número de asientos
        bus = buses_collection.find_one({'_id': ObjectId(bus_id)}) if bus_id else None
        if not bus:
            flash('Debe seleccionar un bus válido')
            return render_template('agregar_ruta.html', buses=buses)

        asientos = bus.get('asientos', 0)  # Tomamos asientos del bus seleccionado

        #Guardar rutas en base a los nodos y las aristas
        nueva_ruta_segmento = {
            'origen': origen,
            'destino': destino,
            'fecha': fecha,
            'hora': hora,
            'asientos_disponibles': asientos, 
            'precio_base': precio_base,
            'bus_id': ObjectId(bus_id),
            'cooperativa_id': ObjectId(cooperativa_id),
            'activa': True 
        }
        rutas_collection.insert_one(nueva_ruta_segmento)
        flash('Ruta agregada correctamente.')
        return redirect(url_for('mostrar_rutas')) 
    return render_template('agregar_ruta.html', buses=buses)

#Mostrar rutas
@app.route('/mostrar_rutas')
@admin_required
def mostrar_rutas():
    coordenadas_ciudades = {
    "Manta": [-0.9677, -80.7089],
    "Guayaquil": [-2.1709, -79.9224],
    "Portoviejo": [-1.0545, -80.4542],
    "Quito": [-0.1807, -78.4678],
    }

    cooperativa_id = current_user.cooperativa_id
    if not cooperativa_id:
        flash('No se pudo identificar la cooperativa')
        return redirect(url_for('dashboard_admin'))

    route_segments = list(rutas_collection.find({'cooperativa_id': ObjectId(cooperativa_id)}))
    graph_nodes = set()
    graph_edges = []

    for segment in route_segments:
        origen = str(segment['origen'])
        destino = str(segment['destino']) 
        graph_nodes.add(origen)
        graph_nodes.add(destino)

        precio_segmento = segment.get('precio_base', 0) # Usar 'precio_base'
        if isinstance(precio_segmento, Decimal128):
            precio_segmento = float(str(precio_segmento)),

        asientos_disponibles = segment.get('asientos_disponibles', 0)
        if isinstance(asientos_disponibles, Decimal128):
            asientos_disponibles = int(str(asientos_disponibles))

        fecha = str(segment.get('fecha', ''))
        hora = str(segment.get('hora', ''))

        graph_edges.append({
            'id': str(segment['_id']),
            'from': origen,
            'to': destino,
            'label': f"${precio_segmento:.2f} ({hora})",
            'data': {
                'fecha': fecha,
                'hora': hora,
                'precio_segmento': precio_segmento,
                'asientos_disponibles': asientos_disponibles,
                'bus_id': str(segment['bus_id']),
                'cooperativa_id': str(segment['cooperativa_id']),
                'coordenadas': [
                    coordenadas_ciudades.get(origen),
                    coordenadas_ciudades.get(destino)
                ]
            }
        })

    nodes_for_frontend = [{'id': city, 'label': city} for city in sorted(list(graph_nodes))]
    rutas_serializadas = [serializar_ruta(r) for r in rutas_collection.find({'cooperativa_id': ObjectId(cooperativa_id)})]

    return render_template(
        'rutas.html',
        rutas=rutas_serializadas,
        nodes_for_frontend=nodes_for_frontend,
        graph_edges=graph_edges
    )

#Eliminar buses
@app.route('/eliminar_bus/<bus_id>')
@admin_required 
def eliminar_bus(bus_id):
    try:
        # Asegurarse de que el bus pertenece a la cooperativa del admin logueado
        result = buses_collection.delete_one({'_id': ObjectId(bus_id), 'cooperativa_id': ObjectId(current_user.cooperativa_id)})
        if result.deleted_count > 0:
            flash('Bus eliminado')
        else:
            flash('Bus no encontrado o no pertenece a tu cooperativa.')
    except Exception as e:
        flash(f'Error al eliminar el bus: {e}')
    
    return redirect(url_for('mostrar_buses'))

#Eliminar rutas
@app.route('/eliminar_ruta/<ruta_id>')
@admin_required
def eliminar_ruta(ruta_id):
    try:
        # Asegurarse de que la ruta pertenece a la cooperativa del admin logueado
        result = rutas_collection.delete_one({'_id': ObjectId(ruta_id), 'cooperativa_id': ObjectId(current_user.cooperativa_id)})
        if result.deleted_count > 0:
            flash('Ruta eliminada')
        else:
            flash('Ruta no encontrada o no pertenece a tu cooperativa.')
    except Exception as e:
        flash(f'Error al eliminar la ruta: {e}')
    
    return redirect(url_for('mostrar_rutas'))

#Llamar a main e iniciar programa
if __name__ == '__main__':
    try:
        # Verificar conexión a MongoDB
        client.admin.command('ping')
        print("Conexión exitosa a MongoDB")
        
        # Inicializar datos
        inicializar_datos()
        
        # Ejecutar la aplicación
        app.run(debug=True)
    except Exception as e:
        print(f"Error al conectar con MongoDB: {e}")
        print("Asegúrate de que MongoDB esté ejecutándose en tu sistema")
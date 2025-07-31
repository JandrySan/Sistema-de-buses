from pymongo import MongoClient
from datetime import datetime
import sys

def verificar_mongodb():
    """Verificar conexión a MongoDB"""
    print("🔍 Verificando conexión a MongoDB...")
    
    try:
        # Intentar conexión sin autenticación
        client = MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        print("✓ MongoDB está corriendo y accesible")
        return client
    except Exception as e:
        print(f"✗ Error de conexión: {e}")
        print("💡 Asegúrate de que MongoDB esté ejecutándose:")
        print("   sudo systemctl start mongod")
        return None

def verificar_base_datos(client):
    """Verificar base de datos del sistema"""
    print("\n📊 Verificando base de datos 'sistema_buses'...")
    
    db = client.sistema_buses
    
    # Verificar colecciones
    colecciones = db.list_collection_names()
    print(f"📁 Colecciones encontradas: {colecciones}")
    
    # Estadísticas de cada colección
    for col_name in ['usuarios', 'rutas', 'buses', 'ventas']:
        if col_name in colecciones:
            count = db[col_name].count_documents({})
            print(f"   {col_name}: {count} documentos")
        else:
            print(f"   {col_name}: No existe (se creará automáticamente)")
    
    return db

def inicializar_datos_ejemplo(db):
    """Inicializar datos de ejemplo si no existen"""
    print("\n🔧 Inicializando datos de ejemplo...")
    
    # Usuarios
    # Usuarios
    if db.usuarios.count_documents({}) == 0:
        usuarios = [
            {'username': 'admin', 'password': '123', 'role': 'admin'},              # administrador de cooperativa
            {'username': 'admin_general', 'password': 'admin123', 'role': 'admin_general'},  # administrador general
            {'username': 'empleado', 'password': '456', 'role': 'empleado'},
            {'username': 'cliente', 'password': 'cliente123', 'role': 'cliente'}    # usuario externo
        ]
        db.usuarios.insert_many(usuarios)
        print("✓ Usuarios inicializados (admin, admin_general, empleado, cliente)")

    
    # Rutas
    if db.rutas.count_documents({}) == 0:
        rutas = [
            {"origen": "Quito", "destino": "Guayaquil", "fecha": "15-06-2025", "hora": "08:00", "asientos": 45, "precio_base": 25.0},
            {"origen": "Manta", "destino": "Quito", "fecha": "16-06-2025", "hora": "10:00", "asientos": 47, "precio_base": 30.0},
            {"origen": "Manta", "destino": "Portoviejo", "fecha": "16-06-2025", "hora": "10:00", "asientos": 47, "precio_base": 8.0},
            {"origen": "Portoviejo", "destino": "Manta", "fecha": "16-06-2025", "hora": "10:00", "asientos": 47, "precio_base": 8.0},
            {"origen": "Manta", "destino": "Guayaquil", "fecha": "16-06-2025", "hora": "10:00", "asientos": 40, "precio_base": 20.0}
        ]
        db.rutas.insert_many(rutas)
        print("✓ Rutas inicializadas")
    
    # Agregar algunos buses de ejemplo
    if db.buses.count_documents({}) == 0:
        buses_ejemplo = [
            {
                'cedula': 1723456789, 'nombres': 'Juan Carlos', 'apellidos': 'Pérez López',
                'placa': 'ABC-1234', 'marca': 'Mercedes Benz', 'combustible': 'Diesel',
                'color': 'Azul', 'motor': 'OM 926', 'ruedas': 6,
                'pasajeros': 45, 'asientos': 45,
                'fecha_registro': datetime.now().strftime('%d-%m-%Y %H:%M')
            },
            {
                'cedula': 1798765432, 'nombres': 'María Elena', 'apellidos': 'González Ruiz',
                'placa': 'XYZ-5678', 'marca': 'Volvo', 'combustible': 'Diesel',
                'color': 'Blanco', 'motor': 'D13A', 'ruedas': 6,
                'pasajeros': 47, 'asientos': 47,
                'fecha_registro': datetime.now().strftime('%d-%m-%Y %H:%M')
            }
        ]
        db.buses.insert_many(buses_ejemplo)
        print("✓ Buses de ejemplo inicializados")

def mostrar_resumen(db):
    """Mostrar resumen de la base de datos"""
    print("\n" + "="*50)
    print("📋 RESUMEN DE LA BASE DE DATOS")
    print("="*50)
    
    stats = {
        'Usuarios': db.usuarios.count_documents({}),
        'Rutas': db.rutas.count_documents({}),
        'Buses': db.buses.count_documents({}),
        'Ventas': db.ventas.count_documents({}),
        'Reservas': db.ventas.count_documents({'estado': 'reservado'})
    }
    
    for categoria, cantidad in stats.items():
        print(f"{categoria:.<20} {cantidad:>3}")
    
    print("="*50)
    
    # Mostrar usuarios disponibles
    print("\n👥 USUARIOS DISPONIBLES:")
    usuarios = db.usuarios.find({}, {'_id': 0, 'password': 0})
    for user in usuarios:
        print(f"   • {user['username']} ({user['role']})")

def main():
    """Función principal"""
    print("🚌 CONFIGURADOR DE MONGODB - SISTEMA DE BUSES")
    print("="*50)
    
    # Verificar MongoDB
    client = verificar_mongodb()
    if not client:
        sys.exit(1)
    
    # Verificar base de datos
    db = verificar_base_datos(client)
    
    # Inicializar datos
    inicializar_datos_ejemplo(db)
    
    # Mostrar resumen
    mostrar_resumen(db)
    
    print("\n✅ Configuración completada!")
    print("💡 Ahora puedes ejecutar la aplicación Flask:")
    print("   python app.py")
    
    client.close()

if __name__ == "__main__":
    main()

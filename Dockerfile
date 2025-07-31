# Usa una imagen base oficial de Python
FROM python:3.10

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia el contenido del proyecto al contenedor
COPY . /app

# Instala pip y dependencias del proyecto
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Expone el puerto donde Flask correrá (opcional si usas 5000)
EXPOSE 5000

# Comando por defecto para iniciar la app
CMD ["python", "app.py"]

import socket
import struct
import hashlib

class Paquete:
    def __init__(self, numero_secuencia, datos, indicador_fin):
        self.numero_secuencia = numero_secuencia
        self.datos = datos.encode('utf-8')
        self.longitud = len(self.datos)
        self.checksum = self.calcular_checksum()
        self.indicador_fin = indicador_fin

    def calcular_checksum(self):
        m = hashlib.sha256()
        m.update(self.datos)
        return m.digest()[:4]

    def empacar(self):
        cabecera = struct.pack('!II', self.numero_secuencia, self.longitud)
        indicador = struct.pack('!?', self.indicador_fin)
        return cabecera + self.datos + self.checksum + indicador

# ====================
# Cliente
# ====================

HOST = '0.0.0.0'
PORT = 4466

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    mensajes = ["Hola servidor", "Segundo paquete", "Fin de la comunicación"]

    for i, mensaje in enumerate(mensajes):
        fin = True if i == len(mensajes) - 1 else False
        p = Paquete(i + 1, mensaje, fin)
        s.sendall(p.empacar())
        print(f"Paquete {i + 1} enviado: {mensaje}")
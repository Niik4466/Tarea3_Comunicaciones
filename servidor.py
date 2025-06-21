import socket
import struct
import hashlib

class Paquete:
    def __init__(self, numero_secuencia, datos, indicador_fin):
        self.numero_secuencia = numero_secuencia
        self.datos = datos
        self.longitud = len(datos)
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

    @staticmethod
    def desempaquetar(sock):
        def recv_exacto(sock, n):
            """Recibe exactamente n bytes o lanza error."""
            data = b''
            while len(data) < n:
                packet = sock.recv(n - len(data))
                if not packet:
                    raise ConnectionError("Conexión cerrada prematuramente")
                data += packet
            return data

        cabecera = recv_exacto(sock, 8)
        numero_secuencia, longitud = struct.unpack('!II', cabecera)
        datos = recv_exacto(sock, longitud)
        checksum = recv_exacto(sock, 4)
        indicador_fin = struct.unpack('!?', recv_exacto(sock, 1))[0]

        p = Paquete(numero_secuencia, datos, indicador_fin)
        if p.checksum != checksum:
            raise ValueError("Checksum inválido. Paquete corrupto.")
        return p

# ====================
# Servidor
# ====================

HOST = '0.0.0.0'
PORT = 4466

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    print(f'[*] Esperando conexión en el puerto {PORT}...')

    s.bind((HOST, PORT))
    
    s.listen()
    print(f"Servidor escuchando en {HOST}:{PORT}")
    conn, addr = s.accept()
    with conn:
        print(f"Conexión establecida con {addr}")
        while True:
            try:
                paquete = Paquete.desempaquetar(conn)
                print(f"Paquete recibido:")
                print(f"  Secuencia: {paquete.numero_secuencia}")
                print(f"  Longitud: {paquete.longitud}")
                print(f"  Datos: {paquete.datos.decode('utf-8')}")
                print(f"  Checksum: {paquete.checksum.hex()}")
                print(f"  Indicador fin: {paquete.indicador_fin}")
                if paquete.indicador_fin:
                    print("Fin de la transmisión.")
                    break
            except ConnectionError:
                print("Cliente cerró la conexión.")
                break
            except Exception as e:
                print("Error:", e)
                break
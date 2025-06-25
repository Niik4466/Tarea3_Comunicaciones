import socket
from protocolo import StopAndWait, CFG

# ====================
# Cliente UDP (Stop-and-Wait)
# ====================

HOST = '127.0.0.1'  # Cambia si el servidor está en otra IP
PORT = 4466

mensajes = [
    "Hola servidor",
    "Segundo paquete",
    "Fin de la comunicación"
]

cfg = CFG(timeout=1.0, key=0xAA)  # Configuración (timeout, clave XOR)

# Creamos socket UDP
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    protocolo = StopAndWait(sock, (HOST, PORT), cfg)

    for i, mensaje in enumerate(mensajes):
        print(f"Enviando paquete {i}: {mensaje}")
        protocolo.send_data(mensaje.encode('utf-8'))
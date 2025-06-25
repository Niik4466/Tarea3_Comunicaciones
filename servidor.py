import socket
from protocolo import StopAndWait, CFG

# ====================
# Servidor UDP (Stop-and-Wait)
# ====================

HOST = '0.0.0.0'
PORT = 4466

cfg = CFG(timeout=1.0, key=0xAA)  # Misma configuración que el cliente

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind((HOST, PORT))
    print(f"[Servidor] Escuchando en {HOST}:{PORT}...")

    protocolo = StopAndWait(sock, None, cfg)

    while True:
        data, addr = protocolo.wait_data()
        if data is None:
            print("[Servidor] Paquete dañado o duplicado, ignorado.")
            continue

        mensaje = data.decode('utf-8')
        print(f"[Servidor] Mensaje recibido desde {addr}: {mensaje}")

        if mensaje == "Fin de la comunicación":
            print("[Servidor] Fin detectado. Cerrando servidor.")
            break
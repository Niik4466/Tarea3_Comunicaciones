import socket
from protocolo import StopAndWait, CFG, ErrorSimulator

# ====================
# Servidor UDP (Stop-and-Wait)
# ====================

HOST = 'localhost'
PORT = 4466

cfg = CFG(timeout=1.0, key=0xAA)  # Misma configuración que el cliente

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind((HOST, PORT))
    print(f"[Servidor] Escuchando en {HOST}:{PORT}...")

    errsim = ErrorSimulator(p_dup=0.0)
    protocolo = StopAndWait(sock, None, cfg, error_sim=errsim)


    while True:
        data, addr = protocolo.receive_message()
        if data is None:
            print("No se recibió ningún mensaje. Continuando...")
            continue
        
        mensaje = data.decode('utf-8')
        print(f"[Servidor] Mensaje recibido desde {addr}: {mensaje}")


import socket
from protocolo import StopAndWait, CFG, ErrorSimulator

# ====================
# Cliente UDP (Stop-and-Wait)
# ====================


HOST = 'localhost'  # Cambia si el servidor está en otra IP
PORT = 4466


mensajes = [
    "Hola servidor",
    "Segundo paquete",
    "Tercer mensaje",
    "Cuarto mensaje",
    "Quinto mensaje",
    "Fin de la comunicación"
]

cfg = CFG(timeout=1.0, key=0xAA)  # Configuración (timeout, clave XOR)

# Creamos socket UDP
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:

    # Simulador de errores (opcional)
    # Puedes ajustar los parámetros de p_loss, p_dup y p_err según lo que quieras
    errsim = ErrorSimulator(p_loss=0.0, p_dup=0.0, p_err=0.0, p_ack_dup=0, timeout=0)  # Ajusta según lo que quieras probar

    #errsim = ErrorSimulator(p_loss=0.2, p_dup=0.1, p_err=0.3)  # Ajusta según lo que quieras probar
    protocolo = StopAndWait(sock, (HOST, PORT), cfg, error_sim=errsim)


    for i, mensaje in enumerate(mensajes):
        print(f"[Cliente] Enviando mensaje {i}: {mensaje}")
        protocolo.send_message(mensaje.encode('utf-8'))

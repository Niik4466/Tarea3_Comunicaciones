import socket
from protocolo import StopAndWait, CFG, ErrorSimulator

# ====================
# Cliente UDP (Stop-and-Wait)
# ====================


HOST = 'localhost'  # Cambia si el servidor está en otra IP
PORT = 4466


mensajes = [
    "Hola servidor",
    "Lorem ipsum dolor sit amet consectetur adipiscing elit nullam, penatibus metus cubilia nulla faucibus cum vivamus, gravida congue nunc vulputate tincidunt urna leo. Quis varius ultrices pretium convallis mi orci proin, pulvinar hac cras aenean libero curae himenaeos, eget feugiat euismod conubia sagittis elementum. Eget sodales sociis lacus natoque et auctor ac leo mus nascetur, velit porttitor etiam arcu proin duis parturient himenaeos aptent mauris, blandit faucibus sociosqu sagittis habitant cras lacinia ligula scelerisque. Sed congue lobortis volutpat mollis laoreet nostra faucibus montes felis nunc, molestie tincidunt scelerisque suspendisse urna sociosqu luctus sem.",
    "Mauris id lacinia netus conubia sodales sociosqu molestie nascetur accumsan scelerisque, maecenas parturient egestas magnis sed cubilia malesuada fermentum erat senectus enim, urna tristique luctus ultricies felis curae vitae pulvinar posuere. Euismod arcu natoque tempus habitant dictumst curae ultricies, in fusce risus conubia malesuada sodales ad a, sagittis tempor placerat class dictum at. Elementum proin non dapibus vehicula turpis parturient praesent quisque sociosqu, sem mattis dictum sagittis malesuada cum ridiculus class, imperdiet penatibus sed enim potenti pretium dignissim mus. Ac odio molestie tristique luctus dui sollicitudin neque pulvinar faucibus sapien nostra, velit viverra egestas conubia mollis urna cras sociosqu diam tempus, sodales lobortis eget torquent blandit rutrum nascetur auctor montes venenatis.",
    "Fin de la comunicación",
]

cfg = CFG(timeout=1.0, key=0xAA)  # Configuración (timeout, clave XOR)

# Creamos socket UDP
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:

    # Simulador de errores (opcional)
    # Puedes ajustar los parámetros de p_loss, p_dup y p_err según lo que quieras
    errsim = ErrorSimulator(p_loss=0.0, p_dup=0.0, p_err=0.0)

    #errsim = ErrorSimulator(p_loss=0.2, p_dup=0.1, p_err=0.3)
    protocolo = StopAndWait(sock, (HOST, PORT), cfg, error_sim=errsim)


    for i, mensaje in enumerate(mensajes):
        print(f"[Cliente] Enviando mensaje {i}: {mensaje}")
        protocolo.send_message(mensaje.encode('utf-8'))

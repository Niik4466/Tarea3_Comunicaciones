# protocolo.py
import struct, random, time, socket
from enum import IntEnum

EOP = 0x7E                 # Indicador fin de paquete ----------

class PType(IntEnum):
    DATA = 1
    ACK  = 2
    NAK  = 3


## TODO
# Hacer paquete

class Packet:
    _HDR_FMT = "<BBH"      # seq, ptype, length

    def __init__(self, seq: int, ptype: int, payload: bytes = b''):
        self.seq, self.ptype, self.payload = seq, PType(ptype), payload
        self.length = len(payload) 

    def to_bytes(self):
        hdr = struct.pack(self._HDR_FMT, self.seq, self.ptype, self.length)
        body = hdr + self.payload
        crc_bytes  = CRC16IBM.aplicar(body)
        return body + crc_bytes + bytes([EOP])

    @classmethod
    def from_bytes(cls, raw: bytes):
        if raw[-1] != EOP:
            raise ValueError("EOP faltante")
        
        packet_wo_eop = raw[:-1]                 # quita EOP
        #tamaño del encabezado
        hdr_size = struct.calcsize(cls._HDR_FMT)
        #desempaquetar encabezado
        seq, ptype, length = struct.unpack(cls._HDR_FMT, packet_wo_eop)
        #Extraer payload y CRC recibido
        payload = packet_wo_eop[hdr_size:-2]
        crc_bytes = packet_wo_eop[-2:]  # últimos 2 bytes son el CRC
        # Crear instancia y validar CRC
        pkt = cls(seq, ptype, payload)
        # Si validar devuelve False, el paquete está corrupto
        pkt.corrupt = not CRC16IBM.validar(packet_wo_eop[:-2], crc_bytes) 
        return pkt


class CRC16IBM:

    @staticmethod
    def aplicar(data: bytes) -> bytes:
        """Retorna los 2 bytes del CRC-16/IBM para los datos dados."""
        return struct.pack("<H", CRC16IBM.compute(data))


    @staticmethod
    def validar(data: bytes, crc_rx: bytes) -> bool:
        """Valida el CRC-16/IBM del paquete."""
        crc_val = struct.unpack("<H", crc_rx)[0] # Desempaqueta el CRC recibido
        return CRC16IBM.compute(data) == crc_val


    @staticmethod
    def compute(data: bytes) -> int:
        """Calcula el CRC-16/IBM para los datos dados."""
        crc = 0xFFFF
        for b in data:
            crc ^= b
            for _ in range(8):
                crc = (crc >> 1) ^ 0xA001 if (crc & 1) else (crc >> 1)
        return crc & 0xFFFF

## TODO
# Validar q te weno
class CipherXOR:

    def __init__(self, key: int = 0xAA):
        self.key = key
    def encrypt(self, data: bytes) -> bytes:
        return bytes(b ^ self.key for b in data)
    decrypt = encrypt

## TODO
# Agregar errores propuestos en el mensaje fijado en discord (Josefain)
class ErrorSimulator:
    def __init__(self, p_loss=0.1, p_dup=0.1, p_err=0.1, p_ack_dup=0.1, timeout=1.0):
        """
        p_loss: probabilidad de pérdida del paquete
        p_dup: probabilidad de duplicación del paquete
        p_err: probabilidad de corrupción del paquete
        p_ack_dup: probabilidad de duplicar el ACK (simulando retardo)
        timeout: usado para simular el retardo de ACK
        """
        self.p_loss = p_loss
        self.p_dup = p_dup
        self.p_err = p_err
        self.p_ack_dup = p_ack_dup
        self.timeout = timeout
        self.ack_buffer = None  # almacena un ACK para duplicar más tarde

    def maybe_drop(self) -> bool:
        """Decide si un paquete se pierde."""
        return random.random() < self.p_loss

    def maybe_dup(self) -> bool:
        """Decide si un paquete se duplica (se envía dos veces)."""
        return random.random() < self.p_dup

    def maybe_corrupt(self, frame: bytearray) -> None:
        """Aplica corrupción a un paquete con probabilidad p_err."""
        if random.random() < self.p_err and len(frame) > 0:
            i = random.randrange(len(frame))
            frame[i] ^= 1 << random.randrange(8)

    def maybe_buffer_ack(self, ack_pkt: bytes):
        """Simula que un ACK se retrasa y se enviará más adelante."""
        if random.random() < self.p_ack_dup:
            self.ack_buffer = ack_pkt
            return True  # se retiene
        return False     # se puede enviar normalmente


    def maybe_send_buffered_ack(self, sock, addr):
        """Envía el ACK duplicado guardado, si existe."""
        if self.ack_buffer:
            time.sleep(self.timeout)  # simula retardo
            sock.sendto(self.ack_buffer, addr)
            self.ack_buffer = None


class CFG:
    """
    Configuración del protocolo Stop-and-Wait
    Contiene parámetros como timeout y clave de cifrado.
    """
    def __init__(self, timeout=1.0, key=0xAA):
        self.timeout = timeout
        self.key = key


class StopAndWait:
    """
    Protocolo Stop-and-Wait
    Implementación del protocolo Stop-and-Wait con corrección de errores.
    Utiliza XOR para cifrado y CRC-16/IBM para verificación de integridad

    Parámetros:
    - sock: socket UDP para la comunicación
    - peer: dirección del destinatario
    - cfg: configuración del protocolo
    - error_sim: simulador de errores (opcional)
    """
    def __init__(self, sock: socket.socket, peer, cfg, error_sim=None):
        self.sock, self.peer = sock, peer
        self.cipher = CipherXOR(cfg.key)
        self.errsim = error_sim or ErrorSimulator() # Simulador de errores por defecto, ocupa la clase ErrorSimulator para simular errores
        self.timeout = cfg.timeout
        self.seq = 0

        # Para receptor
        self.addrTransmitter = None  # Dirección del emisor, se establece al recibir el primer paquete

    # ------------- EMISOR -------------

    def send_data(self, data: bytes):
        """
        Envía datos utilizando el protocolo Stop-and-Wait basado en el AFD descrito en el informe.
        Si se recibe un ACK, se incrementa la secuencia.
        """
        pkt = Packet(self.seq, PType.DATA, self.cipher.encrypt(data))
        frame = bytearray(pkt.to_bytes())
        ackRecibido = False
        self.sock.settimeout(self.timeout)

        while not ackRecibido: # Mientras no se reciba un ACK
            # TODO Manejo de errores simulado 
            try:
                # Enviamos el paquete
                print("Enviando paquete:", self.seq)
                if not self.errsim.maybe_drop(): #Si no se pierde el paquete
                    # Simula duplicación
                    if self.errsim.maybe_dup():
                        print("[Cliente] Paquete duplicado")
                        self.sock.sendto(frame, self.peer) #y lo vuelve a enviar
                    self.errsim.maybe_corrupt(frame) # o simula corrupción
                    self.sock.sendto(frame, self.peer) #Y lo vuelve a enviar
                else:
                    print("[Cliente] Paquete simulado como perdido") #Se simula que se pierde el paquete


                print("Esperando paquete:", self.seq)
                resp = self.sock.recv(64)  # espera ACK o NAK
                rcv = Packet.from_bytes(resp)

                # Si se recibe ACK correcto, se actualiza la secuencia
                if rcv.ptype == PType.ACK and rcv.seq == self.seq and not rcv.corrupt:
                    ackRecibido = True
                    self.seq ^= 1

                # Si se recibe NAK o el paquete está corrupto, se retransmite
                elif rcv.ptype == PType.NAK or rcv.corrupt:
                    print("Recibido NAK o paquete corrupto, reintentando...")
                    continue  # retransmitir

            except socket.timeout:
                print("Timeout al enviar el paquete, reintentando...")
                continue

    # ------------- RECEPTOR --------------

    def wait_data(self):
        """
        Espera a recibir datos de un emisor.
        """
        frame, addr = self.sock.recvfrom(2048)
        if self.addrTransmitter is None:
            print("Esperando paquete...")
            self.addrTransmitter = addr
        else:
            print(f"Esperando paquete de {self.addrTransmitter}")
        while self.addrTransmitter != addr:
            print(f"Esperando paquete de {self.addrTransmitter}")
            
            frame, addr = self.sock.recvfrom(2048)

        buf = bytearray(frame)

        self.errsim.maybe_corrupt(buf) # Simula corrupción de datos en recepción
        
        # TODO errores simulados
        pkt = Packet.from_bytes(buf) #se crea el paquete a partir del buffer recibido, from_bytes valida CRC y EOP

        if pkt.corrupt or pkt.seq != self.seq:
            nak = Packet(self.seq, PType.NAK)
            print("Paquete corrupto o duplicado, enviando NAK")
            self.sock.sendto(nak.to_bytes(), addr)
            return None, addr
        
        print(f"Paquete recibido: seq={pkt.seq}, ptype={pkt.ptype}, length={pkt.length}")
        print("Enviando ACK")
        ack = Packet(pkt.seq, PType.ACK)

        # Simula que el ACK se retrasa
        ack_pkt = ack.to_bytes()
        if not self.errsim.maybe_buffer_ack(ack_pkt):
            self.sock.sendto(ack_pkt, addr)
        self.errsim.maybe_send_buffered_ack(self.sock, addr)

        self.seq ^= 1
        return self.cipher.decrypt(pkt.payload), addr
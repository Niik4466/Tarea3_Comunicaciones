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

    def __init__(self, seq, ptype, payload=b''):
        self.seq, self.ptype, self.payload = seq, PType(ptype), payload
        self.length = len(payload)

    def to_bytes(self):
        hdr = struct.pack(self._HDR_FMT, self.seq, self.ptype, self.length)
        body = hdr + self.payload
        crc  = struct.pack("<H", CRC16IBM.compute(body))
        return body + crc + bytes([EOP])

    @classmethod
    def from_bytes(cls, raw: bytes):
        if raw[-1] != EOP:
            raise ValueError("EOP faltante")
        raw = raw[:-1]                 # quita EOP
        seq, ptype, length = struct.unpack(cls._HDR_FMT, raw[:4])
        payload, crc_rx = raw[4:-2], struct.unpack("<H", raw[-2:])[0]
        pkt = cls(seq, ptype, payload)
        pkt.corrupt = CRC16IBM.compute(raw[:-2]) != crc_rx
        return pkt

## TODO
# hacer las funciones (ivan)
class CRC16IBM:

    def aplicar() -> None:
        """Aplica el CRC-16/IBM al paquete."""
        pass
    
    def validar() -> bool:
        """Valida el CRC-16/IBM del paquete."""
        pass


    @staticmethod
    def compute(data: bytes) -> int:
        crc = 0xFFFF
        for b in data:
            crc ^= b
            for _ in range(8):
                crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
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
        self.errsim = error_sim or ErrorSimulator()
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
        frame = pkt.to_bytes()
        ackRecibido = False
        self.sock.settimeout(self.timeout)

        while not ackRecibido:
            # TODO Manejo de errores simulado 
            try:
                # Enviamos el paquete
                print("Enviando paquete:", self.seq)
                self.sock.sendto(frame, self.peer)

                print("Esperando paquete:", self.seq)
                resp = self.sock.recv(64)  # espera ACK o NAK
                rcv = Packet.from_bytes(resp)

                # Si se recibe ACK correcto, se actualiza la secuencia
                if rcv.ptype == PType.ACK and rcv.seq == self.seq and not rcv.corrupt:
                    ackRecibido = True
                    self.seq += 1  # Sigue la secuencia

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
        # TODO errores simulados
        pkt = Packet.from_bytes(buf)

        if pkt.corrupt or pkt.seq != self.seq:
            nak = Packet(self.seq, PType.NAK)
            print("Paquete corrupto o duplicado, enviando NAK")
            self.sock.sendto(nak.to_bytes(), addr)
            return None, addr
        
        print(f"Paquete recibido: seq={pkt.seq}, ptype={pkt.ptype}, length={pkt.length}")
        print("Enviando ACK")
        ack = Packet(pkt.seq, PType.ACK)
        self.sock.sendto(ack.to_bytes(), addr)
        self.seq += 1
        return self.cipher.decrypt(pkt.payload), addr
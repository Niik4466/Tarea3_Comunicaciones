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
    def __init__(self, p_loss=0.1, p_dup=0.1, p_err=0.1):
        self.p_loss, self.p_dup, self.p_err = p_loss, p_dup, p_err
    def maybe_drop(self):  return random.random() < self.p_loss
    def maybe_dup (self):  return random.random() < self.p_dup
    def maybe_corrupt(self, frame: bytearray):
        if random.random() < self.p_err:
            i = random.randrange(len(frame))
            frame[i] ^= 1 << random.randrange(8)

## TODO
# Modificar protocolo para que se adapte al AFD propuesto.
# Validar q te weno
# Niik
class StopAndWait:
    def __init__(self, sock: socket.socket, peer, cfg, error_sim=None):
        self.sock, self.peer = sock, peer
        self.cipher = CipherXOR(cfg.key)
        self.errsim = error_sim or ErrorSimulator()
        self.timeout = cfg.timeout
        self.seq_tx, self.seq_rx = 0, 0

    # ------------- EMISOR -------------
    def send(self, data: bytes):
        pkt = Packet(self.seq_tx, PType.DATA,
                     self.cipher.encrypt(data))
        frame = pkt.to_bytes()
        while True:
            if self.errsim.maybe_drop(): pass
            else: self.sock.sendto(frame, self.peer)
            dup = self.errsim.maybe_dup()
            if dup: self.sock.sendto(frame, self.peer)
            t0 = time.time()
            while time.time() - t0 < self.timeout:
                try:
                    self.sock.settimeout(self.timeout-(time.time()-t0))
                    resp, _ = self.sock.recvfrom(64)
                except socket.timeout: break
                rcv = Packet.from_bytes(resp)
                if rcv.ptype == PType.ACK and rcv.seq == self.seq_tx and not rcv.corrupt:
                    self.seq_tx ^= 1
                    return          # éxito
            # timeout o NAK ⇒ retransmitir

    # ------------- RECEPTOR -------------
    def recv(self):
        frame, addr = self.sock.recvfrom(2048)
        buf = bytearray(frame)
        self.errsim.maybe_corrupt(buf)
        pkt = Packet.from_bytes(buf)
        if pkt.corrupt or pkt.seq != self.seq_rx:
            nak = Packet(self.seq_rx, PType.NAK)
            self.sock.sendto(nak.to_bytes(), addr)
            return None, addr
        ack = Packet(pkt.seq, PType.ACK)
        self.sock.sendto(ack.to_bytes(), addr)
        self.seq_rx ^= 1
        return self.cipher.decrypt(pkt.payload), addr

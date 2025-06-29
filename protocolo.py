# protocolo.py
import struct, random, time, socket
from enum import IntEnum
from typing import List

EOP = 0x7E                 # Indicador fin de paquete ----------

class PType(IntEnum):
    DATA = 1
    ACK  = 2
    NAK  = 3

import struct
from protocolo import PType, EOP

class Packet:
    _HDR_FMT = "<BB"           # seq (1B), ptype (1B)
    PAYLOAD_SIZE = 16            # tamaño fijo de payload en bytes

    def __init__(self, seq: int, ptype: int, payload: bytes = b''):
        self.seq = seq
        self.ptype = PType(ptype)
        # Validar y ajustar payload a tamaño fijo
        if len(payload) > self.PAYLOAD_SIZE:
            raise ValueError(f"Payload demasiado largo (máximo {self.PAYLOAD_SIZE} bytes)")
        # Padding con ceros si es menor
        self.payload = payload.ljust(self.PAYLOAD_SIZE, b'\x00')

    def to_bytes(self) -> bytes:
        # Cabecera fija
        hdr = struct.pack(self._HDR_FMT, self.seq, self.ptype)
        # Cuerpo = cabecera + payload fijo
        body = hdr + self.payload
        # CRC sobre cabecera+payload
        crc_bytes = CRC16IBM.aplicar(body)
        return body + crc_bytes + bytes([EOP])

    @classmethod
    def from_bytes(cls, raw: bytes):
        if raw[-1] != EOP:
            pkt = cls(0, PType.NAK, b'')
            pkt.corrupt = True

        packet_wo_eop = raw[:-1]
        hdr_size = struct.calcsize(cls._HDR_FMT)  # 2 bytes
        # Desempaquetar cabecera fija
        seq, ptype = struct.unpack(
            cls._HDR_FMT,
            packet_wo_eop[:hdr_size]
        )
        # Extraer payload de tamaño fijo
        payload = packet_wo_eop[hdr_size: hdr_size + cls.PAYLOAD_SIZE]
        # CRC de 2 bytes justo después del payload
        crc_start = hdr_size + cls.PAYLOAD_SIZE
        crc_bytes = packet_wo_eop[crc_start: crc_start + 2]



        # Validar CRC antes de reconstruir
        if not CRC16IBM.validar(packet_wo_eop[:crc_start], crc_bytes):
            pkt = cls(seq, PType.NAK, b'')
            pkt.corrupt = True
        else:
            try:
                pkt = cls(seq, ptype, payload)
                pkt.corrupt = False
            except ValueError as e:
                pkt = cls(0, PType.NAK, b'')
                pkt.corrupt = True
        return pkt

        # Reconstruir paquete
        # pkt = cls(seq, ptype, payload)
        # # Validar CRC sobre header+payload
        # pkt.corrupt = not CRC16IBM.validar(
        #     packet_wo_eop[:crc_start],
        #     crc_bytes
        # )
        # return pkt

# class Packet:
#     _HDR_FMT = "<BBH"      # seq, ptype, length

#     def __init__(self, seq: int, ptype: int, payload: bytes = b''):
#         self.seq, self.ptype, self.payload = seq, PType(ptype), payload
#         self.length = len(payload) 

#     def to_bytes(self):
#         hdr = struct.pack(self._HDR_FMT, self.seq, self.ptype, self.length)
#         body = hdr + self.payload
#         crc_bytes  = CRC16IBM.aplicar(body)
#         return body + crc_bytes + bytes([EOP])

#     @classmethod
#     def from_bytes(cls, raw: bytes):
#         if raw[-1] != EOP:
#             raise ValueError("EOP faltante")
#         try:
#             packet_wo_eop = raw[:-1]                 # quita EOP
#             #tamaño del encabezado
#             hdr_size = struct.calcsize(cls._HDR_FMT) # = 4 bytes
#             #desempaquetar encabezado
#             seq, ptype, length = struct.unpack(cls._HDR_FMT, packet_wo_eop[:hdr_size])
#             #Extraer payload y CRC recibido
#             payload = packet_wo_eop[hdr_size:hdr_size + length]  # payload
#             crc_bytes = packet_wo_eop[hdr_size+length:hdr_size+length+2]  # CRC bytes 
#             # Crear instancia y validar CRC
#             pkt = cls(seq, ptype, payload)
#             # Si validar devuelve False, el paquete está corrupto
#             pkt.corrupt = not CRC16IBM.validar(packet_wo_eop[: hdr_size + length], crc_bytes)
#         except ValueError as e:
#             pass
#         return pkt


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

class CipherXOR:

    def __init__(self, key: int = 0xAA):
        self.key = key
    def encrypt(self, data: bytes) -> bytes:
        return bytes(b ^ self.key for b in data)
    decrypt = encrypt


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

    def maybe_corrupt(self, frame: bytearray) -> bytearray:
        prob_corrupt = random.random() < self.p_err and len(frame) > 0
        return prob_corrupt, self.corrupt(frame)

    def corrupt(self, frame: bytearray) -> bytearray:
        frame_copy = bytearray(frame)  # copia para no modificar el original
        i = random.randrange(len(frame_copy))
        frame_copy[i] ^= 1 << random.randrange(8)
        return frame_copy



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

        while not ackRecibido:
            try:
                # Enviamos el paquete
                print("[Cliente] Enviando paquete:", self.seq)
                if not self.errsim.maybe_drop(): #Si no se pierde el paquete
                    # Simula duplicación
                    if self.errsim.maybe_dup():
                        print("[Cliente] Paquete duplicado")
                        self.sock.sendto(frame, self.peer) #y lo vuelve a enviar
                    
                    prob_corrupt, corrupt_frame = self.errsim.maybe_corrupt(frame)
                    if prob_corrupt:
                        self.sock.sendto(corrupt_frame, self.peer)
                    else:
                        self.sock.sendto(frame, self.peer) 
                    print("[Cliente] Paquete enviado correctamente")
                    # Envia el paquete
                else:
                    print("[Cliente] Paquete simulado como perdido") #Se simula que se pierde el paquete


                print("[Cliente] Esperando paquete:", self.seq)
                resp = self.sock.recv(64)  # espera ACK o NAK
                rcv = Packet.from_bytes(resp)

                # Verifica si el paquete está corrupto, en ese caso, se espera un ACK o NAK
                while rcv.corrupt or rcv.seq != self.seq:
                    resp = self.sock.recv(64)  # espera ACK o NAK
                    rcv = Packet.from_bytes(resp)

                # Verifica si el paquete recibido es ACK o NAK
                if rcv.ptype == PType.NAK and rcv.seq == self.seq:
                    print("[Cliente] NAK recibido, reintentando...")
                    continue # Reintenta enviar el paquete
                
                print("[Cliente] ACK recibido")
                ackRecibido = True
                self.seq ^= 1

            except socket.timeout:
                print("[Cliente] Timeout al enviar el paquete, reintentando...")
                continue

    # ------------- RECEPTOR --------------
    
    def wait_data(self):
        """
        Espera a recibir datos de un emisor.
        """
        frame, addr = self.sock.recvfrom(2048)
        if self.addrTransmitter is None:
            print("[Servidor] Esperando paquete...")
            self.addrTransmitter = addr
        else:
            print(f"[Servidor] Esperando paquete de {self.addrTransmitter}")
        while self.addrTransmitter != addr:
            print(f"[Servidor] Esperando paquete de {self.addrTransmitter}")
            
            frame, addr = self.sock.recvfrom(2048)

        buf = bytearray(frame)
        
        pkt = Packet.from_bytes(buf) #se crea el paquete a partir del buffer recibido, from_bytes valida CRC y EOP

        # Verifica si el paquete está corrupto
        if pkt.corrupt:
            print("[Servidor] Paquete corrupto, enviando NAK")
            nak = Packet(self.seq, PType.NAK, payload=b'')
            self.sock.sendto(nak.to_bytes(), addr)
            return None, addr
        
        # Verifica si el paquete tiene la secuencia correcta
        if pkt.seq != self.seq:
            print(f"[Servidor] Paquete con secuencia incorrecta: esperado {self.seq}, recibido {pkt.seq}, enviado ACK con secuencia {pkt.seq}")
            ack = Packet(pkt.seq, PType.ACK, payload=b'')
            self.sock.sendto(ack.to_bytes(), addr)
            return None, addr
        
        # Si el paquete es válido, se procesa
        print("[Servidor] Enviando ACK")
        if (errsim := self.errsim) and errsim.maybe_dup():
            print("[Servidor] ACK duplicado")
            ack = Packet(pkt.seq, PType.ACK, payload=b'')
            self.sock.sendto(ack.to_bytes(), addr)
        ack = Packet(pkt.seq, PType.ACK)

        # Simula que el ACK se retrasa
        ack_pkt = ack.to_bytes()
        if not self.errsim.maybe_buffer_ack(ack_pkt): #Si no se retiene el ACK
            self.sock.sendto(ack_pkt, addr) #se envía el ACK inmediatamente
        self.errsim.maybe_send_buffered_ack(self.sock, addr) 

        self.seq ^= 1
        return self.cipher.decrypt(pkt.payload), addr

    def fragment_data(self, data: bytes, size: int = 16) -> List[bytes]:
        """
        Parte `data` en una lista de bloques de longitud fija `size`.
        - Añade un byte 0x00 como terminador en el último fragmento.
        - Rellena con 0x00 hasta completar `size`.
        """
        segments: List[bytes] = []
        for i in range(0, len(data), size):
            chunk = data[i : i + size]
            if len(chunk) < size:
                # marcamos fin de texto y rellenamos
                chunk = chunk + b'\x00'
                chunk = chunk.ljust(size, b'\x00')
            segments.append(chunk)
        return segments

    def assemble_data(self, chunks: List[bytes]) -> bytes:
        """
        Reconstruye el buffer original a partir de `chunks` de tamaño fijo.
        - Une todos los fragmentos y corta en el primer 0x00 (terminador).
        """
        raw = b"".join(chunks)
        # cortamos en el primer terminador nulo
        return raw.split(b'\x00', 1)[0]
    
    def send_message(self, data: bytes):
        # 1) Fragmentamos el buffer en trozos de 16 bytes
        for segment in self.fragment_data(data):
            # 2) Enviamos cada trozo con tu send_data
            self.send_data(segment)

    def receive_message(self) -> bytes:
        """
        Recorre la recepción de varios paquetes y ensambla el mensaje completo.
        Asume que esperas tantos paquetes como sean necesarios hasta timeout/excepción.
        """
        chunks: List[bytes] = []
        while True:
            payload, _ = self.wait_data()
            if payload is None:
                # en caso de NAK o duplicado, wait_data ya reenvió ACK/NAK; volvemos a intentar
                continue
            chunks.append(payload)
            if payload.endswith(b'\x00' * (self.PAYLOAD_SIZE - 1)):
                break

        # 3) Ensamblamos y devolvemos
        return self.assemble_data(chunks)

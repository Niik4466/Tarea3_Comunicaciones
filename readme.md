# Protocolo de Comunicaciones Stop-and-Wait (UDP)

Este proyecto implementa un protocolo de comunicaciones confiables utilizando el mecanismo Stop-and-Wait sobre el protocolo UDP. El diseño incorpora verificación de errores mediante CRC-16-IBM, cifrado simple con XOR, y un simulador de errores para evaluar la robustez del sistema.

## Archivos del proyecto

- `protocolo.py`: Contiene la implementación del protocolo Stop-and-Wait, la estructura del paquete, el cifrado, CRC y el simulador de errores.
- `cliente.py`: Cliente UDP que envía mensajes al servidor utilizando el protocolo implementado.
- `servidor.py`: Servidor UDP que recibe los mensajes, valida su integridad y los reensambla.
- `localtest.sh`: Bash que deja ejecutar simultaneamente servidor y cliente. 

## Requisitos

- Python 3.7 o superior
- No se requieren bibliotecas externas adicionales

## Instrucciones de uso

1. Abrir dos terminales o consolas.

2. En la primera terminal, ejecutar el servidor:

   ```bash
   python3 ./servidor.py
    ````

    El servidor quedará a la espera de mensajes en el puerto 4466.

3. En la segunda terminal, ejecutar el cliente:

   ```bash
   python3 ./cliente.py
   ```

   El cliente enviará una serie de mensajes, que serán fragmentados, cifrados y transmitidos uno a uno mediante el protocolo Stop-and-Wait. El último mensaje es "Fin de la comunicación", que sirve como señal de término.

## Simulación de errores

El sistema permite simular diferentes tipos de errores para poner a prueba la robustez del protocolo. Para ello, se puede configurar la instancia `ErrorSimulator` en `cliente.py` o `servidor.py` con los siguientes parámetros:

```python
errsim = ErrorSimulator(
    p_loss=0.2,    # Probabilidad de pérdida de paquetes
    p_dup=0.1,     # Probabilidad de duplicación de paquetes
    p_err=0.3,     # Probabilidad de corrupción del contenido

)
```

Por defecto, el simulador está configurado con probabilidades en cero para pruebas limpias.

## Características principales

* Fragmentación automática en bloques de 16 bytes.
* Cifrado XOR con clave configurable.
* Verificación de integridad con CRC-16-IBM.
* Control de flujo tipo Stop-and-Wait.
* Detección de fin de sesión mediante mensaje especial.
* Simulador de errores configurable para pruebas de resiliencia.



#!/bin/bash

# Ejecuta el receptor en una terminal nueva
gnome-terminal -- bash -c "python3 servidor.py; exec bash"

# Espera 2 segundos para que el receptor se inicie
sleep 2

# Ejecuta el emisor en otra terminal nueva
gnome-terminal -- bash -c "python3 cliente.py; exec bash"

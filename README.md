# 🔍 Network Scanner

Escáner de red básico en Python. Permite descubrir hosts activos en una subred, escanear puertos abiertos y realizar banner grabbing.

## Uso

### Escanear subred:

```bash
python scanner.py -n 192.168.1

### Escanear Puertos
python scanner.py -t 192.168.1.10 -p 22,80,443

### Escanear puertos y capturar banners
python scanner.py -t 192.168.1.10 -p 80,443 -b

# Importación de librerías necesarias para sockets, hilos, GUI, subprocessos y colas
import socket
import threading
import platform
import subprocess
from tkinter import *
from tkinter import messagebox, filedialog
from tkinter.ttk import Progressbar
from queue import Queue

# Variables globales compartidas
resultados = []                     # Lista de resultados del escaneo
lock = threading.Lock()            # Lock para sincronizar el acceso a recursos compartidos
scan_en_progreso = False           # Bandera que indica si un escaneo está en proceso
puertos_pendientes = Queue()       # Cola de puertos pendientes de escanear

# Función que hace ping a un host para verificar si está activo
def ping_host(host):
    try:
        # Determinar parámetros del comando según el sistema operativo
        param = "-n" if platform.system().lower() == "windows" else "-c"
        timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
        comando = ["ping", param, "1", timeout_param, "1", host]
        result = subprocess.run(comando, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return result.returncode == 0  # Devuelve True si el host responde
    except:
        return False

# Función que realiza un ping sweep en una subred completa
def ping_sweep(subred, salida_text):
    global scan_en_progreso
    resultados.clear()
    salida_text.insert(END, f"\n🔍 Escaneando desde {subred}.1 hasta {subred}.254...\n")

    cola = Queue()
    # Llenar la cola con direcciones IP dentro de la subred
    for i in range(1, 255):
        cola.put(f"{subred}.{i}")

    # Función que trabajan los hilos para hacer ping a cada IP
    def worker():
        while not cola.empty() and scan_en_progreso:
            ip = cola.get()
            if ping_host(ip):
                with lock:
                    resultados.append(ip)
                    salida_text.insert(END, f"✅ Host activo: {ip}\n")
            cola.task_done()

    scan_en_progreso = True
    # Iniciar 100 hilos para procesar el ping sweep
    for _ in range(100):
        threading.Thread(target=worker, daemon=True).start()
    cola.join()
    salida_text.insert(END, "\n🌝 Ping sweep terminado.\n")
    scan_en_progreso = False

# Función para intentar obtener un banner de un puerto TCP
def banner_grab(host, port):
    try:
        sock = socket.socket()
        sock.settimeout(0.3)
        sock.connect((host, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner if banner else "Sin banner"
    except:
        return "No detectado"

# Función para escanear puertos TCP
def escanear_tcp(host, salida_text, barra_progreso, progreso_label):
    global scan_en_progreso, puertos_pendientes
    resultados.clear()
    salida_text.insert(END, f"\n🔍 Escaneando puertos TCP de {host}...\n")

    total = puertos_pendientes.qsize()
    completados = 0

    # Función para que cada hilo escanee un puerto
    def worker():
        nonlocal completados
        while not puertos_pendientes.empty() and scan_en_progreso:
            port = puertos_pendientes.get()
            try:
                sock = socket.socket()
                sock.settimeout(0.3)
                if sock.connect_ex((host, port)) == 0:
                    banner = banner_grab(host, port)
                    with lock:
                        salida_text.insert(END, f"🟢 TCP {port} - {banner}\n")
                        salida_text.see(END)
                sock.close()
            except:
                pass
            completados += 1
            barra_progreso["value"] = (completados / total) * 100
            progreso_label.config(text=f"{int((completados / total) * 100)}%")
            puertos_pendientes.task_done()

    scan_en_progreso = True
    # Lanzar múltiples hilos para paralelizar el escaneo
    for _ in range(100):
        threading.Thread(target=worker, daemon=True).start()
    puertos_pendientes.join()
    salida_text.insert(END, "\n✅ Escaneo TCP terminado.\n")
    scan_en_progreso = False

# Función para escanear puertos UDP
def escanear_udp(host, salida_text, barra_progreso, progreso_label):
    global scan_en_progreso, puertos_pendientes
    resultados.clear()
    salida_text.insert(END, f"\n🔍 Escaneando puertos UDP de {host}...\n")

    total = puertos_pendientes.qsize()
    completados = 0

    def worker():
        nonlocal completados
        while not puertos_pendientes.empty() and scan_en_progreso:
            port = puertos_pendientes.get()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.3)
                sock.sendto(b"", (host, port))
                try:
                    data, _ = sock.recvfrom(1024)
                    with lock:
                        salida_text.insert(END, f"🟢 UDP {port} → {data.decode(errors='ignore').strip()}\n")
                        salida_text.see(END)
                except:
                    pass
                sock.close()
            except:
                pass
            completados += 1
            barra_progreso["value"] = (completados / total) * 100
            progreso_label.config(text=f"{int((completados / total) * 100)}%")
            puertos_pendientes.task_done()

    scan_en_progreso = True
    for _ in range(100):
        threading.Thread(target=worker, daemon=True).start()
    puertos_pendientes.join()
    salida_text.insert(END, "\n✅ Escaneo UDP terminado.\n")
    scan_en_progreso = False

# Función para interpretar el texto de entrada y generar una lista de puertos
def obtener_puertos_desde_entrada(texto):
    if not texto.strip():
        return range(1, 65536)  # Si está vacío, usar todo el rango de puertos
    if "-" in texto:
        inicio, fin = map(int, texto.split("-"))
        return range(inicio, fin + 1)
    elif "," in texto:
        return [int(p) for p in texto.split(",")]
    else:
        return [int(texto.strip())]

# Función principal para iniciar un escaneo
def iniciar_escaneo(ip_entry, puerto_entry, salida_text, barra_progreso, progreso_label, protocolo_var):
    global scan_en_progreso, puertos_pendientes

    if scan_en_progreso:
        messagebox.showinfo("Escaneo en curso", "🚠 Ya hay un escaneo en proceso.")
        return

    host = ip_entry.get().strip()
    puerto_texto = puerto_entry.get().strip()

    # Validar IP o dominio
    try:
        socket.gethostbyname(host)
    except:
        messagebox.showerror("Error", "IP o dominio inválido.")
        return

    try:
        puertos = obtener_puertos_desde_entrada(puerto_texto)
    except:
        messagebox.showerror("Error", "Formato de puertos inválido.")
        return

    # Limpiar la cola antes de llenarla con nuevos puertos
    while not puertos_pendientes.empty():
        puertos_pendientes.get()

    for port in puertos:
        puertos_pendientes.put(port)

    # Reiniciar barra de progreso
    barra_progreso["value"] = 0
    progreso_label.config(text="0%")

    # Lanzar el escaneo según el protocolo seleccionado
    if protocolo_var.get() == "TCP":
        threading.Thread(target=escanear_tcp, args=(host, salida_text, barra_progreso, progreso_label), daemon=True).start()
    else:
        threading.Thread(target=escanear_udp, args=(host, salida_text, barra_progreso, progreso_label), daemon=True).start()

# Función para reanudar un escaneo pausado
def reanudar_escaneo(ip_entry, salida_text, barra_progreso, progreso_label, protocolo_var):
    global scan_en_progreso
    if scan_en_progreso:
        messagebox.showinfo("Ya en ejecución", "⏳ Ya hay un escaneo en curso.")
        return

    host = ip_entry.get().strip()
    try:
        socket.gethostbyname(host)
    except:
        messagebox.showerror("Error", "IP o dominio inválido.")
        return

    if puertos_pendientes.empty():
        messagebox.showinfo("Sin pendientes", "📬 No hay puertos pendientes para reanudar.")
        return

    if protocolo_var.get() == "TCP":
        threading.Thread(target=escanear_tcp, args=(host, salida_text, barra_progreso, progreso_label), daemon=True).start()
    else:
        threading.Thread(target=escanear_udp, args=(host, salida_text, barra_progreso, progreso_label), daemon=True).start()

# Función para detener un escaneo en curso
def detener_escaneo():
    global scan_en_progreso
    scan_en_progreso = False

# Función para guardar los resultados en un archivo de texto
def guardar_resultado(salida_text):
    archivo = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Archivo de texto", "*.txt")])
    if archivo:
        with open(archivo, "w", encoding="utf-8") as f:
            f.write(salida_text.get("1.0", END))
        messagebox.showinfo("Guardado", f"✅ Resultados guardados en:\n{archivo}")

# Función para limpiar la salida de resultados
def limpiar_resultados(salida_text):
    salida_text.delete("1.0", END)

# Función para iniciar el ping sweep desde la interfaz
def iniciar_ping(ip_entry, salida_text):
    ip = ip_entry.get().strip()
    partes = ip.split(".")
    if len(partes) == 4 and partes[-1] == "0":
        ip = ".".join(partes[:3])
    elif len(partes) != 3:
        messagebox.showerror("Error", "Formato de subred inválido. Ejemplo: 192.168.1")
        return
    threading.Thread(target=ping_sweep, args=(ip, salida_text), daemon=True).start()

# Función principal que crea y lanza la interfaz gráfica
def main():
    ventana = Tk()
    ventana.title("🚁 Escáner de Red tipo Nmap - GUI")
    ventana.geometry("800x700")
    ventana.resizable(False, False)

    # Campos de entrada
    Label(ventana, text="IP/Dominio:").pack()
    ip_entry = Entry(ventana, width=60)
    ip_entry.pack()

    Label(ventana, text="Puertos (ej. vacío, 1-1024, 22,80,443):").pack()
    puerto_entry = Entry(ventana, width=60)
    puerto_entry.pack()

    # Selección del protocolo
    protocolo_var = StringVar(value="TCP")
    frame_protocolo = Frame(ventana)
    frame_protocolo.pack()
    Radiobutton(frame_protocolo, text="TCP", variable=protocolo_var, value="TCP").pack(side=LEFT)
    Radiobutton(frame_protocolo, text="UDP", variable=protocolo_var, value="UDP").pack(side=LEFT)

    # Barra de progreso y etiqueta
    barra_progreso = Progressbar(ventana, length=600, mode="determinate")
    barra_progreso.pack(pady=5)
    progreso_label = Label(ventana, text="0%")
    progreso_label.pack()

    # Cuadro de salida
    salida = Text(ventana, height=20, width=95)
    salida.pack(pady=10)

    # Botones de acciones
    frame_botones = Frame(ventana)
    frame_botones.pack()
    Button(frame_botones, text="🔍 Escanear", command=lambda: iniciar_escaneo(ip_entry, puerto_entry, salida, barra_progreso, progreso_label, protocolo_var)).pack(side=LEFT, padx=5)
    Button(frame_botones, text="⛔ Detener", command=detener_escaneo).pack(side=LEFT, padx=5)
    Button(frame_botones, text="▶️ Reanudar", command=lambda: reanudar_escaneo(ip_entry, salida, barra_progreso, progreso_label, protocolo_var)).pack(side=LEFT, padx=5)
    Button(frame_botones, text="📂 Guardar", command=lambda: guardar_resultado(salida)).pack(side=LEFT, padx=5)
    Button(frame_botones, text="🩹 Limpiar", command=lambda: limpiar_resultados(salida)).pack(side=LEFT, padx=5)

    # Ping sweep
    Label(ventana, text="Subred para ping sweep (ej. 192.168.1):").pack(pady=(20, 0))
    subred_entry = Entry(ventana, width=50)
    subred_entry.pack()
    Button(ventana, text="📡 Ping Sweep", command=lambda: iniciar_ping(subred_entry, salida)).pack(pady=5)

    ventana.mainloop()

# Iniciar la aplicación
if __name__ == "__main__":
    main()

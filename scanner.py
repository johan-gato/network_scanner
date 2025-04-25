# Importación de librerías necesarias
import socket               # Para crear conexiones de red
import threading            # Para ejecutar tareas en paralelo
import platform             # Para identificar el sistema operativo
import subprocess           # Para ejecutar comandos del sistema (ping)
from tkinter import *       # Para crear la interfaz gráfica (GUI)
from tkinter import messagebox, filedialog  # Para mostrar mensajes y guardar archivos
from tkinter.ttk import Progressbar         # Barra de progreso
from queue import Queue     # Cola para manejar tareas en múltiples hilos

# Lista global para almacenar resultados
resultados = []

# Bloqueo para evitar que múltiples hilos modifiquen resultados al mismo tiempo
lock = threading.Lock()

# Bandera global para controlar si el escaneo está activo
scan_en_progreso = False

# Función para hacer ping a un host y verificar si está activo
def ping_host(host):
    try:
        # Determina parámetros dependiendo del SO
        param = "-n" if platform.system().lower() == "windows" else "-c"
        timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
        comando = ["ping", param, "1", timeout_param, "1", host]
        # Ejecuta el ping
        result = subprocess.run(comando, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except:
        return False

# Función para hacer un barrido de ping a una subred
def ping_sweep(subred, salida_text):
    global scan_en_progreso
    resultados.clear()
    salida_text.insert(END, f"\n🔍 Escaneando desde {subred}.1 hasta {subred}.254...\n")
    cola = Queue()

    # Rango de IPs a escanear
    for i in range(1, 255):
        cola.put(f"{subred}.{i}")

    # Función de hilo que hace ping a cada IP
    def worker():
        while not cola.empty() and scan_en_progreso:
            ip = cola.get()
            if ping_host(ip):
                with lock:
                    resultados.append(ip)
                    salida_text.insert(END, f"✅ Host activo: {ip}\n")
            cola.task_done()

    scan_en_progreso = True

    # Inicia múltiples hilos
    for _ in range(100):
        threading.Thread(target=worker, daemon=True).start()

    cola.join()
    salida_text.insert(END, "\n🏁 Ping sweep terminado.\n")
    scan_en_progreso = False

# Obtiene el banner de un puerto TCP abierto
def banner_grab(host, port):
    try:
        sock = socket.socket()
        sock.settimeout(0.3)
        sock.connect((host, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")  # Solicitud simple HTTP
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner if banner else "Sin banner"
    except:
        return "No detectado"

# Función para escanear puertos TCP
def escanear_tcp(host, puertos, salida_text, barra_progreso, progreso_label):
    global scan_en_progreso
    resultados.clear()
    salida_text.insert(END, f"\n🔍 Escaneando puertos TCP de {host}...\n")
    cola = Queue()
    total = len(puertos)
    completados = 0

    # Carga puertos en cola
    for port in puertos:
        cola.put(port)

    # Función de escaneo TCP en hilo
    def worker():
        nonlocal completados
        while not cola.empty() and scan_en_progreso:
            port = cola.get()
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
            cola.task_done()

    scan_en_progreso = True

    # Lanza hilos para escaneo TCP
    for _ in range(100):
        threading.Thread(target=worker, daemon=True).start()

    cola.join()
    salida_text.insert(END, "\n✅ Escaneo TCP terminado.\n")
    scan_en_progreso = False

# Función para escanear puertos UDP
def escanear_udp(host, puertos, salida_text, barra_progreso, progreso_label):
    global scan_en_progreso
    resultados.clear()
    salida_text.insert(END, f"\n🔍 Escaneando puertos UDP de {host}...\n")
    cola = Queue()
    total = len(puertos)
    completados = 0

    for port in puertos:
        cola.put(port)

    def worker():
        nonlocal completados
        while not cola.empty() and scan_en_progreso:
            port = cola.get()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.5)
                sock.sendto(b"", (host, port))
                try:
                    data, _ = sock.recvfrom(1024)
                    with lock:
                        salida_text.insert(END, f"🟢 UDP {port} → {data.decode(errors='ignore').strip()}\n")
                        salida_text.see(END)
                except (socket.timeout, socket.error):
                    pass  # No mostrar si no hay respuesta
                sock.close()
            except:
                pass
            completados += 1
            barra_progreso["value"] = (completados / total) * 100
            progreso_label.config(text=f"{int((completados / total) * 100)}%")
            cola.task_done()

    scan_en_progreso = True
    for _ in range(100):
        threading.Thread(target=worker, daemon=True).start()

    cola.join()
    salida_text.insert(END, "\n✅ Escaneo UDP terminado.\n")
    scan_en_progreso = False

# Procesa el texto de entrada para obtener los puertos
def obtener_puertos_desde_entrada(texto):
    if not texto.strip():
        return range(1, 65536)
    if "-" in texto:
        inicio, fin = map(int, texto.split("-"))
        return range(inicio, fin + 1)
    elif "," in texto:
        return [int(p) for p in texto.split(",")]
    else:
        return [int(texto.strip())]

# Inicia escaneo según el protocolo (TCP/UDP)
def iniciar_escaneo(ip_entry, puerto_entry, salida_text, barra_progreso, progreso_label, protocolo_var):
    host = ip_entry.get().strip()
    puerto_texto = puerto_entry.get().strip()

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

    barra_progreso["value"] = 0
    progreso_label.config(text="0%")

    if protocolo_var.get() == "TCP":
        threading.Thread(target=escanear_tcp, args=(host, puertos, salida_text, barra_progreso, progreso_label), daemon=True).start()
    else:
        threading.Thread(target=escanear_udp, args=(host, puertos, salida_text, barra_progreso, progreso_label), daemon=True).start()

# Inicia barrido de ping
def iniciar_ping(ip_entry, salida_text):
    ip = ip_entry.get().strip()
    partes = ip.split(".")
    if len(partes) == 4 and partes[-1] == "0":
        ip = ".".join(partes[:3])
    elif len(partes) != 3:
        messagebox.showerror("Error", "Formato de subred inválido. Ejemplo: 192.168.1")
        return
    threading.Thread(target=ping_sweep, args=(ip, salida_text), daemon=True).start()

# Guarda los resultados en un archivo .txt
def guardar_resultado(salida_text):
    archivo = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Archivo de texto", "*.txt")])
    if archivo:
        with open(archivo, "w", encoding="utf-8") as f:
            f.write(salida_text.get("1.0", END))
        messagebox.showinfo("Guardado", f"✅ Resultados guardados en:\n{archivo}")

# Borra el contenido del área de resultados
def limpiar_resultados(salida_text):
    salida_text.delete("1.0", END)

# Detiene el escaneo en curso
def detener_escaneo():
    global scan_en_progreso
    scan_en_progreso = False

# Interfaz principal
def main():
    ventana = Tk()
    ventana.title("🛰️ Escáner de Red tipo Nmap - GUI")
    ventana.geometry("800x700")
    ventana.resizable(False, False)

    # Entrada de IP y puertos
    Label(ventana, text="IP/Dominio:").pack()
    ip_entry = Entry(ventana, width=60)
    ip_entry.pack()

    Label(ventana, text="Puertos (ej. vacío, 1-1024, 22,80,443):").pack()
    puerto_entry = Entry(ventana, width=60)
    puerto_entry.pack()

    # Selección de protocolo (TCP/UDP)
    protocolo_var = StringVar(value="TCP")
    frame_protocolo = Frame(ventana)
    frame_protocolo.pack()
    Radiobutton(frame_protocolo, text="TCP", variable=protocolo_var, value="TCP").pack(side=LEFT)
    Radiobutton(frame_protocolo, text="UDP", variable=protocolo_var, value="UDP").pack(side=LEFT)

    # Barra de progreso
    barra_progreso = Progressbar(ventana, length=600, mode="determinate")
    barra_progreso.pack(pady=5)
    progreso_label = Label(ventana, text="0%")
    progreso_label.pack()

    # Área de salida
    salida = Text(ventana, height=20, width=95)
    salida.pack(pady=10)

    # Botones organizados horizontalmente
    frame_botones = Frame(ventana)
    frame_botones.pack()
    Button(frame_botones, text="Escanear", command=lambda: iniciar_escaneo(ip_entry, puerto_entry, salida, barra_progreso, progreso_label, protocolo_var)).pack(side=LEFT, padx=5)
    Button(frame_botones, text="Detener", command=detener_escaneo).pack(side=LEFT, padx=5)
    Button(frame_botones, text="Guardar", command=lambda: guardar_resultado(salida)).pack(side=LEFT, padx=5)
    Button(frame_botones, text="Limpiar", command=lambda: limpiar_resultados(salida)).pack(side=LEFT, padx=5)

    # Sección ping sweep
    Label(ventana, text="Subred para ping sweep (ej. 192.168.1):").pack(pady=(20, 0))
    subred_entry = Entry(ventana, width=50)
    subred_entry.pack()
    Button(ventana, text="Ping Sweep", command=lambda: iniciar_ping(subred_entry, salida)).pack(pady=5)

    ventana.mainloop()

# Llama a la interfaz si se ejecuta como script
if __name__ == "__main__":
    main()

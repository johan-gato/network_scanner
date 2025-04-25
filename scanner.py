# Importación de librerías necesarias
import socket               # Para conexiones de red
import threading            # Para ejecutar tareas en paralelo
import platform             # Para detectar el sistema operativo
import subprocess           # Para ejecutar comandos del sistema
from tkinter import *       # Para la interfaz gráfica
from tkinter import messagebox, filedialog  # Para ventanas emergentes y guardar archivos
from tkinter.ttk import Progressbar         # Barra de progreso de la GUI
from queue import Queue     # Para manejo de tareas en cola

# Lista global para almacenar resultados
resultados = []

# Bloqueo para evitar que varios hilos modifiquen resultados al mismo tiempo
lock = threading.Lock()

# Función que realiza un ping a un host
def ping_host(host):
    try:
        # Determina parámetros de ping según el sistema operativo
        param = "-n" if platform.system().lower() == "windows" else "-c"
        timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
        comando = ["ping", param, "1", timeout_param, "1", host]
        
        # Ejecuta el ping y revisa si responde
        result = subprocess.run(comando, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception as e:
        print(f"Error al hacer ping a {host}: {e}")
        return False

# Función para hacer ping sweep (barrido de red)
def ping_sweep(subred, salida_text):
    resultados.clear()  # Limpia resultados anteriores
    salida_text.insert(END, f"\n🔍 Escaneando desde {subred}.1 hasta {subred}.254...\n")
    cola = Queue()

    # Agrega IPs de la subred a la cola
    for i in range(1, 255):
        ip = f"{subred}.{i}"
        cola.put(ip)

    # Función que ejecutan los hilos para hacer ping a cada IP
    def worker():
        while not cola.empty():
            ip = cola.get()
            if ping_host(ip):
                with lock:
                    resultados.append(ip)
                    salida_text.insert(END, f"✅ Host activo: {ip}\n")
            cola.task_done()

    # Crea y lanza múltiples hilos para el ping
    for _ in range(100):
        t = threading.Thread(target=worker, daemon=True)
        t.start()

    cola.join()  # Espera a que todos los hilos terminen
    salida_text.insert(END, "\n🏁 Ping sweep terminado.\n")

# Intenta obtener el banner de un puerto abierto (respuesta del servidor)
def banner_grab(host, port):
    try:
        sock = socket.socket()
        sock.settimeout(0.3)
        sock.connect((host, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")  # Envia solicitud HTTP
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner if banner else "Sin banner"
    except:
        return "No detectado"

# Escanea puertos y muestra resultados con progreso
def escanear_puertos(host, puertos, salida_text, barra_progreso, progreso_label):
    resultados.clear()
    salida_text.insert(END, f"\n🔍 Escaneando puertos de {host}...\n")
    cola = Queue()

    total = len(puertos)  # Total de puertos
    completados = 0       # Contador de progreso

    # Agrega todos los puertos a la cola
    for port in puertos:
        cola.put(port)

    # Función ejecutada por cada hilo para escanear puertos
    def worker():
        nonlocal completados
        while not cola.empty():
            port = cola.get()
            try:
                sock = socket.socket()
                sock.settimeout(0.3)
                result = sock.connect_ex((host, port))
                if result == 0:
                    banner = banner_grab(host, port)
                    with lock:
                        resultados.append((port, banner))
                        salida_text.insert(END, f"🟢 Puerto abierto: {port} - {banner}\n")
                        salida_text.see(END)
                sock.close()
            except:
                pass
            completados += 1
            # Actualiza barra de progreso
            barra_progreso["value"] = (completados / total) * 100
            progreso_label.config(text=f"{int((completados / total) * 100)}%")
            cola.task_done()

    # Crea múltiples hilos para escanear más rápido
    for _ in range(150):
        t = threading.Thread(target=worker, daemon=True)
        t.start()

    cola.join()  # Espera a que terminen
    salida_text.insert(END, "\n✅ Escaneo de puertos terminado.\n")

# Convierte el texto ingresado en una lista o rango de puertos
def obtener_puertos_desde_entrada(texto):
    if not texto.strip():
        return range(1, 65536)  # Todos los puertos si está vacío
    if "-" in texto:
        inicio, fin = map(int, texto.split("-"))
        return range(inicio, fin + 1)
    elif "," in texto:
        return [int(p) for p in texto.split(",")]
    else:
        return [int(texto.strip())]

# Llama al escaneo de puertos en un hilo nuevo
def iniciar_escaneo_puertos(ip_entry, puerto_entry, salida_text, barra_progreso, progreso_label):
    host = ip_entry.get().strip()
    puerto_texto = puerto_entry.get().strip()

    try:
        socket.gethostbyname(host)  # Verifica si es una IP válida
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

    # Lanza el escaneo en un hilo para no congelar la GUI
    threading.Thread(target=escanear_puertos, args=(host, puertos, salida_text, barra_progreso, progreso_label), daemon=True).start()

# Llama al ping sweep en un hilo nuevo
def iniciar_ping(ip_entry, salida_text):
    ip = ip_entry.get().strip()
    partes = ip.split(".")

    if len(partes) == 4 and partes[-1] == "0":
        ip = ".".join(partes[:3])
    elif len(partes) != 3:
        messagebox.showerror("Error", "Formato de subred inválido. Ejemplo: 192.168.1")
        return

    threading.Thread(target=ping_sweep, args=(ip, salida_text), daemon=True).start()

# Guarda los resultados mostrados en pantalla en un archivo .txt
def guardar_resultado(salida_text):
    archivo = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Archivo de texto", "*.txt")])
    if archivo:
        with open(archivo, "w", encoding="utf-8") as f:
            f.write(salida_text.get("1.0", END))
        messagebox.showinfo("Guardado", f"✅ Resultados guardados en:\n{archivo}")

# Limpia la salida de resultados en la interfaz
def limpiar_resultados(salida_text):
    salida_text.delete("1.0", END)

# Función principal que construye la interfaz gráfica
def main():
    ventana = Tk()
    ventana.title("🛰️ Escáner de Red tipo Nmap - GUI con Progreso")
    ventana.geometry("770x670")
    ventana.resizable(False, False)

    # Entrada para IP
    Label(ventana, text="IP/Dominio para escanear puertos:").pack()
    ip_entry = Entry(ventana, width=50)
    ip_entry.pack()

    # Entrada para puertos
    Label(ventana, text="Puertos (vacío = todos, 1-1024, 22,80,443):").pack()
    puerto_entry = Entry(ventana, width=50)
    puerto_entry.pack()

    # Barra de progreso
    barra_progreso = Progressbar(ventana, length=600, mode="determinate")
    barra_progreso.pack(pady=5)
    progreso_label = Label(ventana, text="0%")
    progreso_label.pack()

    # Cuadro de salida de texto
    salida = Text(ventana, height=20, width=90)
    salida.pack(pady=10)

    # Botón para escaneo de puertos
    Button(ventana, text="Escanear Puertos", command=lambda: iniciar_escaneo_puertos(ip_entry, puerto_entry, salida, barra_progreso, progreso_label)).pack(pady=5)

    # Entrada para subred
    Label(ventana, text="Subred para ping sweep (ej. 192.168.1):").pack(pady=(20, 0))
    subred_entry = Entry(ventana, width=50)
    subred_entry.pack()
    
    # Botón para hacer ping sweep
    Button(ventana, text="Ping Sweep", command=lambda: iniciar_ping(subred_entry, salida)).pack(pady=5)

    # Botón para guardar resultados
    Button(ventana, text="Guardar Resultados", command=lambda: guardar_resultado(salida)).pack(pady=5)

    # Botón para limpiar resultados
    Button(ventana, text="🧹 Limpiar Resultados", command=lambda: limpiar_resultados(salida)).pack(pady=5)

    ventana.mainloop()  # Inicia la interfaz gráfica

# Ejecuta la app si se corre directamente
if __name__ == "__main__":
    main()

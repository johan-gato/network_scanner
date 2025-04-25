import socket
import threading
import platform
import subprocess
from tkinter import *
from tkinter import messagebox, filedialog
from tkinter.ttk import Progressbar
from queue import Queue

resultados = []
lock = threading.Lock()

def ping_host(host):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
        comando = ["ping", param, "1", timeout_param, "1", host]
        result = subprocess.run(comando, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception as e:
        print(f"Error al hacer ping a {host}: {e}")
        return False

def ping_sweep(subred, salida_text):
    resultados.clear()
    salida_text.delete("1.0", END)
    salida_text.insert(END, f"🔍 Escaneando desde {subred}.1 hasta {subred}.254...\n")
    cola = Queue()
    for i in range(1, 255):
        ip = f"{subred}.{i}"
        cola.put(ip)

    def worker():
        while not cola.empty():
            ip = cola.get()
            if ping_host(ip):
                with lock:
                    resultados.append(ip)
                    salida_text.insert(END, f"✅ Host activo: {ip}\n")
            cola.task_done()

    for _ in range(100):
        t = threading.Thread(target=worker, daemon=True)
        t.start()

    cola.join()
    salida_text.insert(END, "\n🏁 Ping sweep terminado.\n")

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

def escanear_puertos(host, puertos, salida_text, barra_progreso, progreso_label):
    resultados.clear()
    salida_text.delete("1.0", END)
    salida_text.insert(END, f"🔍 Escaneando puertos de {host}...\n")
    cola = Queue()

    total = len(puertos)
    completados = 0

    for port in puertos:
        cola.put(port)

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
            barra_progreso["value"] = (completados / total) * 100
            progreso_label.config(text=f"{int((completados / total) * 100)}%")
            cola.task_done()

    for _ in range(150):
        t = threading.Thread(target=worker, daemon=True)
        t.start()

    cola.join()
    salida_text.insert(END, "\n✅ Escaneo de puertos terminado.\n")

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

def iniciar_escaneo_puertos(ip_entry, puerto_entry, salida_text, barra_progreso, progreso_label):
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

    threading.Thread(target=escanear_puertos, args=(host, puertos, salida_text, barra_progreso, progreso_label), daemon=True).start()

def iniciar_ping(ip_entry, salida_text):
    ip = ip_entry.get().strip()
    partes = ip.split(".")
    
    if len(partes) == 4 and partes[-1] == "0":
        ip = ".".join(partes[:3])
    elif len(partes) != 3:
        messagebox.showerror("Error", "Formato de subred inválido. Ejemplo: 192.168.1")
        return

    threading.Thread(target=ping_sweep, args=(ip, salida_text), daemon=True).start()

def guardar_resultado(salida_text):
    archivo = filedialog.asksaveasfilename(defaultextension=".txt")
    if archivo:
        with open(archivo, "w") as f:
            f.write(salida_text.get("1.0", END))
        messagebox.showinfo("Guardado", f"Resultados guardados en {archivo}")

def main():
    ventana = Tk()
    ventana.title("🛰️ Escáner de Red tipo Nmap - GUI con Progreso")
    ventana.geometry("770x630")
    ventana.resizable(False, False)

    Label(ventana, text="IP/Dominio para escanear puertos:").pack()
    ip_entry = Entry(ventana, width=50)
    ip_entry.pack()

    Label(ventana, text="Puertos (vacío = todos, 1-1024, 22,80,443):").pack()
    puerto_entry = Entry(ventana, width=50)
    puerto_entry.pack()

    barra_progreso = Progressbar(ventana, length=600, mode="determinate")
    barra_progreso.pack(pady=5)
    progreso_label = Label(ventana, text="0%")
    progreso_label.pack()

    Button(ventana, text="Escanear Puertos", command=lambda: iniciar_escaneo_puertos(ip_entry, puerto_entry, salida, barra_progreso, progreso_label)).pack(pady=5)

    Label(ventana, text="Subred para ping sweep (ej. 192.168.1):").pack(pady=(20, 0))
    subred_entry = Entry(ventana, width=50)
    subred_entry.pack()
    Button(ventana, text="Ping Sweep", command=lambda: iniciar_ping(subred_entry, salida)).pack(pady=5)

    salida = Text(ventana, height=20, width=90)
    salida.pack(pady=10)

    Button(ventana, text="Guardar Resultados", command=lambda: guardar_resultado(salida)).pack(pady=5)

    ventana.mainloop()

if __name__ == "__main__":
    main()


import socket
import threading
import platform
import subprocess
from tkinter import *
from tkinter import messagebox, filedialog
from tkinter.ttk import Progressbar
from queue import Queue

# Variables globales
resultados = []
lock = threading.Lock()
scan_en_progreso = False

def ping_host(host):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
        comando = ["ping", param, "1", timeout_param, "1", host]
        result = subprocess.run(comando, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except:
        return False

def ping_sweep(subred, salida_text):
    global scan_en_progreso
    resultados.clear()
    salida_text.insert(END, f"\n🔍 Escaneando desde {subred}.1 hasta {subred}.254...\n")
    cola = Queue()
    for i in range(1, 255):
        ip = f"{subred}.{i}"
        cola.put(ip)

    def worker():
        while not cola.empty() and scan_en_progreso:
            ip = cola.get()
            if ping_host(ip):
                with lock:
                    resultados.append(ip)
                    salida_text.insert(END, f"✅ Host activo: {ip}\n")
            cola.task_done()

    scan_en_progreso = True
    for _ in range(100):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
    cola.join()
    salida_text.insert(END, "\n🏁 Ping sweep terminado.\n")
    scan_en_progreso = False

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

def escanear_tcp(host, puertos, salida_text, barra_progreso, progreso_label):
    global scan_en_progreso
    resultados.clear()
    salida_text.insert(END, f"\n🔍 Escaneando puertos TCP de {host}...\n")
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
                sock = socket.socket()
                sock.settimeout(0.3)
                result = sock.connect_ex((host, port))
                if result == 0:
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
    for _ in range(100):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
    cola.join()
    salida_text.insert(END, "\n✅ Escaneo TCP terminado.\n")
    scan_en_progreso = False

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
                except socket.timeout:
                    pass
                except socket.error:
                    pass
                sock.close()
            except Exception:
                pass

            completados += 1
            barra_progreso["value"] = (completados / total) * 100
            progreso_label.config(text=f"{int((completados / total) * 100)}%")
            cola.task_done()

    scan_en_progreso = True
    for _ in range(100):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
    cola.join()
    salida_text.insert(END, "\n✅ Escaneo UDP terminado.\n")
    scan_en_progreso = False

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

    protocolo = protocolo_var.get()
    if protocolo == "TCP":
        threading.Thread(target=escanear_tcp, args=(host, puertos, salida_text, barra_progreso, progreso_label), daemon=True).start()
    else:
        threading.Thread(target=escanear_udp, args=(host, puertos, salida_text, barra_progreso, progreso_label), daemon=True).start()

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
    archivo = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Archivo de texto", "*.txt")])
    if archivo:
        with open(archivo, "w", encoding="utf-8") as f:
            f.write(salida_text.get("1.0", END))
        messagebox.showinfo("Guardado", f"✅ Resultados guardados en:\n{archivo}")

def limpiar_resultados(salida_text):
    salida_text.delete("1.0", END)

def detener_escaneo():
    global scan_en_progreso
    scan_en_progreso = False

def main():
    ventana = Tk()
    ventana.title("🛰️ Escáner de Red tipo Nmap - GUI")
    ventana.geometry("800x700")
    ventana.resizable(True, True)

    Label(ventana, text="IP/Dominio:").pack()
    ip_entry = Entry(ventana, width=60)
    ip_entry.pack()

    Label(ventana, text="Puertos (ej. vacío, 1-1024, 22,80,443):").pack()
    puerto_entry = Entry(ventana, width=60)
    puerto_entry.pack()

    protocolo_var = StringVar(value="TCP")
    frame_protocolo = Frame(ventana)
    frame_protocolo.pack()
    Checkbutton(frame_protocolo, text="TCP", variable=protocolo_var, onvalue="TCP", offvalue="UDP").pack(side=LEFT)
    Checkbutton(frame_protocolo, text="UDP", variable=protocolo_var, onvalue="UDP", offvalue="TCP").pack(side=LEFT)

    barra_progreso = Progressbar(ventana, length=600, mode="determinate")
    barra_progreso.pack(pady=5)
    progreso_label = Label(ventana, text="0%")
    progreso_label.pack()

    salida = Text(ventana, height=20, width=95)
    salida.pack(pady=10)

    frame_botones = Frame(ventana)
    frame_botones.pack()

    Button(frame_botones, text="Escanear", command=lambda: iniciar_escaneo(ip_entry, puerto_entry, salida, barra_progreso, progreso_label, protocolo_var)).pack(side=LEFT, padx=5)
    Button(frame_botones, text="Detener", command=detener_escaneo).pack(side=LEFT, padx=5)
    Button(frame_botones, text="Guardar", command=lambda: guardar_resultado(salida)).pack(side=LEFT, padx=5)
    Button(frame_botones, text="Limpiar", command=lambda: limpiar_resultados(salida)).pack(side=LEFT, padx=5)

    Label(ventana, text="Subred para ping sweep (ej. 192.168.1):").pack(pady=(20, 0))
    subred_entry = Entry(ventana, width=50)
    subred_entry.pack()
    Button(ventana, text="Ping Sweep", command=lambda: iniciar_ping(subred_entry, salida)).pack(pady=5)

    ventana.mainloop()

if __name__ == "__main__":
    main()


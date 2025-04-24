import socket
import threading
from tkinter import *
from tkinter import messagebox
from tkinter.ttk import Progressbar
from queue import Queue

# Escaneo de un puerto
def scan_port(host, port, timeout=0.1):
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except:
                banner = "Sin banner"
            finally:
                sock.close()
            return port, banner
    except:
        return None

# Escaneo total con barra
def port_scan_all(host):
    resultado_text.insert(END, f"Escaneando todos los puertos de {host}...\n")
    resultado_text.update()

    total_ports = 65535
    completados = 0
    resultados = []
    cola = Queue()

    for port in range(1, total_ports + 1):
        cola.put(port)

    def worker():
        nonlocal completados
        while not cola.empty():
            port = cola.get()
            result = scan_port(host, port)
            completados += 1
            progreso = int((completados / total_ports) * 100)
            barra_progreso["value"] = progreso
            progreso_label.config(text=f"{progreso}%")
            ventana.update_idletasks()

            if result:
                resultados.append(result)
                resultado_text.insert(END, f"[✓] Puerto {result[0]} abierto: {result[1]}\n")
                resultado_text.see(END)
            cola.task_done()

    for _ in range(500):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()

    cola.join()
    resultado_text.insert(END, "\n✅ Escaneo completado.\n")
    resultado_text.see(END)

def iniciar_escaneo_thread():
    resultado_text.delete(1.0, END)
    barra_progreso["value"] = 0
    progreso_label.config(text="0%")
    ip = entrada_ip.get().strip()
    if not ip:
        messagebox.showwarning("Error", "Debes ingresar una dirección IP.")
        return
    t = threading.Thread(target=port_scan_all, args=(ip,))
    t.start()

# GUI
ventana = Tk()
ventana.title("Escáner de Puertos con Progreso")
ventana.geometry("750x540")

Label(ventana, text="Dirección IP a escanear:").pack(pady=5)
entrada_ip = Entry(ventana, width=30)
entrada_ip.pack()

Button(ventana, text="Iniciar Escaneo", command=iniciar_escaneo_thread).pack(pady=10)

barra_progreso = Progressbar(ventana, length=600, mode="determinate")
barra_progreso.pack(pady=5)

progreso_label = Label(ventana, text="0%")
progreso_label.pack()

resultado_text = Text(ventana, height=23, width=90)
resultado_text.pack(pady=10)

ventana.mainloop()

# Importación de librerías necesarias
import socket
import threading
import platform
import subprocess
from tkinter import *
from tkinter import messagebox, filedialog
from tkinter.ttk import Progressbar
from queue import Queue
import time
from multiprocessing import Value

# Lista global para almacenar resultados
resultados = []

# Bloqueo para evitar que múltiples hilos modifiquen la salida de texto al mismo tiempo
lock = threading.Lock()

# Banderas globales para controlar el escaneo
scan_en_progreso = False
scan_pausado = False
pause_event = threading.Event()

# Función para hacer ping a un host y verificar si está activo
def ping_host(host):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
    comando = ["ping", param, "1", timeout_param, "1", host]
    try:
        result = subprocess.run(comando, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=1)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except OSError:
        return False

# Función para hacer un barrido de ping a una subred
def ping_sweep(subred, salida_text, cola_ping):
    global scan_en_progreso, scan_pausado
    resultados.clear()
    salida_text.insert(END, f"\n🔍 Escaneando desde {subred}.1 hasta {subred}.254...\n")

    for i in range(1, 255):
        cola_ping.put(f"{subred}.{i}")

    def worker():
        while scan_en_progreso:
            if scan_pausado:
                pause_event.wait()
            try:
                ip = cola_ping.get(timeout=0.1)
                if ping_host(ip):
                    with lock:
                        resultados.append(ip)
                        salida_text.insert(END, f"✅ Host activo: {ip}\n")
            except Queue.Empty:
                break
            except Exception as e:
                with lock:
                    salida_text.insert(END, f"Error en ping sweep: {e}\n")
            finally:
                cola_ping.task_done()

    scan_en_progreso = True
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(100)]
    for thread in threads:
        thread.start()

    cola_ping.join()
    salida_text.insert(END, "\n🏁 Ping sweep terminado.\n")
    scan_en_progreso = False

# Obtiene el banner de un puerto TCP abierto
def banner_grab(host, port):
    try:
        with socket.socket() as sock:
            sock.settimeout(0.3)
            sock.connect((host, port))
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode(errors="ignore").strip()
            return banner if banner else None
    except (socket.timeout, ConnectionRefusedError):
        return None
    except OSError:
        return None

# Función para escanear puertos TCP y mostrar solo los abiertos
def escanear_tcp(host, puertos, salida_text, barra_progreso, progreso_label, cola_tcp, completados_tcp, total_tcp):
    global scan_en_progreso, scan_pausado
    salida_text.insert(END, f"\n🔍 Escaneando puertos TCP de {host}...\n")

    for port in puertos:
        cola_tcp.put(port)
    total_tcp.value = len(puertos)
    completados_tcp.value = 0

    def worker():
        while scan_en_progreso:
            if scan_pausado:
                pause_event.wait()
            try:
                port = cola_tcp.get(timeout=0.1)
                try:
                    with socket.socket() as sock:
                        sock.settimeout(0.3)
                        result = sock.connect_ex((host, port))
                        if result == 0:
                            banner = banner_grab(host, port)
                            service_info = f"🟢 TCP {port}"
                            if banner:
                                service_info += f" - {banner}"
                            with lock:
                                salida_text.insert(END, f"{service_info}\n")
                                salida_text.see(END)
                except socket.error as e:
                    with lock:
                        salida_text.insert(END, f"Error al escanear puerto TCP {port}: {e}\n")
                        salida_text.see(END)
                finally:
                    with lock:
                        completados_tcp.value += 1
                        if total_tcp.value > 0:
                            barra_progreso["value"] = (completados_tcp.value / total_tcp.value) * 100
                            progreso_label.config(text=f"{int(barra_progreso['value'])}%")
                        cola_tcp.task_done()
            except Queue.Empty:
                break
            except Exception as e:
                with lock:
                    salida_text.insert(END, f"Error en escaneo TCP: {e}\n")

    scan_en_progreso = True
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(100)]
    for thread in threads:
        thread.start()

    cola_tcp.join()
    salida_text.insert(END, "\n✅ Escaneo TCP terminado.\n")
    scan_en_progreso = False

# Función para escanear puertos UDP y mostrar solo los abiertos con información
def escanear_udp(host, puertos, salida_text, barra_progreso, progreso_label, cola_udp, completados_udp, total_udp):
    global scan_en_progreso, scan_pausado
    salida_text.insert(END, f"\n🔍 Escaneando puertos UDP de {host}...\n")

    for port in puertos:
        cola_udp.put(port)
    total_udp.value = len(puertos)
    completados_udp.value = 0

    def worker():
        nonlocal completados_udp
        while scan_en_progreso:
            if scan_pausado:
                pause_event.wait()
            try:
                port = cola_udp.get(timeout=0.1)
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        sock.settimeout(0.5)
                        try:
                            # Envía un paquete vacío para intentar obtener una respuesta
                            sock.sendto(b"", (host, port))
                            data, _ = sock.recvfrom(1024)
                            banner = data.decode(errors='ignore').strip()
                            with lock:
                                salida_text.insert(END, f"🟢 UDP {port} - Abierto")
                                if banner:
                                    salida_text.insert(END, f" - {banner}")
                                salida_text.insert(END, "\n")
                                salida_text.see(END)
                        except socket.timeout:
                            # Si hay timeout, podría estar abierto o filtrado, no lo mostramos para ser más específico
                            pass
                        except OSError as e:
                            # Ignoramos errores de puerto cerrado para no mostrarlos
                            if e.errno == 10054 if platform.system().lower() == "windows" else e.errno == 111:
                                pass
                            else:
                                with lock:
                                    salida_text.insert(END, f"Advertencia al escanear UDP {port}: {e}\n")
                                    salida_text.see(END)
                except socket.error as e:
                    with lock:
                        salida_text.insert(END, f"Error al enviar UDP al puerto {port}: {e}\n")
                        salida_text.see(END)
                finally:
                    with lock:
                        completados_udp.value += 1
                        if total_udp.value > 0:
                            barra_progreso["value"] = (completados_udp.value / total_udp.value) * 100
                            progreso_label.config(text=f"{int(barra_progreso['value'])}%")
                        cola_udp.task_done()
            except Queue.Empty:
                break
            except Exception as e:
                with lock:
                    salida_text.insert(END, f"Error en escaneo UDP: {e}\n")

    scan_en_progreso = True
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(100)]
    for thread in threads:
        thread.start()

    cola_udp.join()
    salida_text.insert(END, "\n✅ Escaneo UDP terminado.\n")
    scan_en_progreso = False

# Procesa el texto de entrada para obtener los puertos
def obtener_puertos_desde_entrada(texto):
    texto = texto.strip()
    if not texto:
        return range(1, 65536)
    puertos = set()
    for parte in texto.split(','):
        parte = parte.strip()
        if '-' in parte:
            try:
                inicio, fin = map(int, parte.split('-'))
                puertos.update(range(inicio, fin + 1))
            except ValueError:
                messagebox.showerror("Error", f"Formato de rango de puertos inválido: {parte}")
                return sorted(list(puertos))
        else:
            try:
                puertos.add(int(parte))
            except ValueError:
                messagebox.showerror("Error", f"Formato de puerto inválido: {parte}")
                return sorted(list(puertos))
    return sorted(list(puertos))

# Función para pausar el escaneo
def pausar_escaneo():
    global scan_pausado
    scan_pausado = True
    pause_button.config(state=DISABLED)
    continuar_button.config(state=NORMAL)

# Función para continuar el escaneo
def continuar_escaneo():
    global scan_pausado
    scan_pausado = False
    pause_event.set()
    pause_event.clear()
    continuar_button.config(state=DISABLED)
    pause_button.config(state=NORMAL)

# Inicia escaneo según el protocolo (TCP/UDP)
def iniciar_escaneo(ip_entry, puerto_entry, salida_text, barra_progreso, progreso_label, protocolo_var, cola_tcp, completados_tcp, total_tcp, cola_udp, completados_udp, total_udp):
    global scan_en_progreso, scan_pausado
    host = ip_entry.get().strip()
    puerto_texto = puerto_entry.get().strip()

    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        messagebox.showerror("Error", "IP o dominio inválido.")
        return

    try:
        puertos = obtener_puertos_desde_entrada(puerto_texto)
    except ValueError:
        messagebox.showerror("Error", "Formato de puertos inválido.")
        return

    barra_progreso["value"] = 0
    progreso_label.config(text="0%")
    salida_text.insert(END, f"Iniciando escaneo tipo Nmap para {host}...\n")
    scan_pausado = False
    pause_event.clear()
    pause_button.config(state=NORMAL)
    continuar_button.config(state=DISABLED)
    scan_en_progreso = True

    if protocolo_var.get() == "TCP":
        threading.Thread(target=escanear_tcp, args=(host, list(puertos), salida_text, barra_progreso, progreso_label, cola_tcp, completados_tcp, total_tcp), daemon=True).start()
    else:
        threading.Thread(target=escanear_udp, args=(host, list(puertos), salida_text, barra_progreso, progreso_label, cola_udp, completados_udp, total_udp), daemon=True).start()

# Inicia barrido de ping
def iniciar_ping(ip_entry, salida_text, cola_ping):
    global scan_en_progreso, scan_pausado
    ip = ip_entry.get().strip()
    partes = ip.split(".")
    if len(partes) == 4 and partes[-1] == "0":
        subred = ".".join(partes[:3])
        threading.Thread(target=ping_sweep, args=(subred, salida_text, cola_ping), daemon=True).start()
    elif len(partes) == 3:
        threading.Thread(target=ping_sweep, args=(".".join(partes), salida_text, cola_ping), daemon=True).start()
    else:
        messagebox.showerror("Error", "Formato de subred inválido. Ejemplo: 192.168.1 o 192.168.1.0")
    scan_pausado = False
    pause_event.clear()
    pause_button.config(state=NORMAL)
    continuar_button.config(state=DISABLED)
    scan_en_progreso = True

# Guarda los resultados en un archivo .txt
def guardar_resultado(salida_text):
    archivo = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Archivo de texto", "*.txt")])
    if archivo:
        try:
            with open(archivo, "w", encoding="utf-8") as f:
                f.write(salida_text.get("1.0", END))
            messagebox.showinfo("Guardado", f"✅ Resultados guardados en:\n{archivo}")
        except Exception as e:
            messagebox.showerror("Error al guardar", f"No se pudo guardar el archivo: {e}")

# Borra el contenido del área de resultados
def limpiar_resultados(salida_text):
    salida_text.delete("1.0", END)

# Detiene el escaneo en curso
def detener_escaneo():
    global scan_en_progreso, scan_pausado
    scan_en_progreso = False
    scan_pausado = False
    pause_event.set()
    pause_button.config(state=DISABLED)
    continuar_button.config(state=DISABLED)

# Interfaz principal
def main():
    ventana = Tk()
    ventana.title("🛰️ Escáner de Red tipo Nmap - GUI")
    ventana.geometry("800x750")
    ventana.resizable(False, False)

    # Variables compartidas para el escaneo
    cola_tcp = Queue()
    completados_tcp = Value('i', 0)
    total_tcp = Value('i', 0)
    cola_udp = Queue()
    completados_udp = Value('i', 0)
    total_udp = Value('i', 0)
    cola_ping = Queue()

    # Entrada de IP y puertos
    Label(ventana, text="IP/Dominio:").pack()
    ip_entry = Entry(ventana, width=60)
    ip_entry.pack()

    Label(ventana, text="Puertos (ej. vacío para todos, 1-1024, 22,80,443):").pack()
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

    # Botones de control de escaneo
    frame_botones_scan = Frame(ventana)
    frame_botones_scan.pack()
    global pause_button, continuar_button
    Button(frame_botones_scan, text="Escanear", command=lambda: iniciar_escaneo(ip_entry, puerto_entry, salida, barra_progreso, progreso_label, protocolo_var, cola_tcp, completados_tcp, total_tcp, cola_udp, completados_udp, total_udp)).pack(side=LEFT, padx=5)
    pause_button = Button(frame_botones_scan, text="Pausar", command=pausar_escaneo, state=DISABLED)
    pause_button.pack(side=LEFT, padx=5)
    continuar_button = Button(frame_botones_scan, text="Continuar", command=continuar_escaneo, state=DISABLED)
    continuar_button.pack(side=LEFT, padx=5)
    Button(frame_botones_scan, text="Detener", command=detener_escaneo).pack(side=LEFT, padx=5)

    # Botones de gestión de resultados
    frame_botones_gestion = Frame(ventana)
    frame_botones_gestion.pack(pady=10)
    Button(frame_botones_gestion, text="Guardar", command=lambda: guardar_resultado(salida)).pack(side=LEFT, padx=5)
    Button(frame_botones_gestion, text="Limpiar", command=lambda: limpiar_resultados(salida)).pack(side=LEFT, padx=5)

    # Sección ping sweep
    Label(ventana, text="Subred para ping sweep (ej. 192.168.1):").pack(pady=(20, 0))
    subred_entry = Entry(ventana, width=50)
    subred_entry.pack()
    Button(ventana, text="Ping Sweep", command=lambda: iniciar_ping(subred_entry, salida, cola_ping)).pack(pady=5)

    ventana.mainloop()

# Llama a la interfaz si se ejecuta como script
if __name__ == "__main__":
    main() 

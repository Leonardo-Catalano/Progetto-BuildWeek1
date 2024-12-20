import socket
import time

#Funzione per scansionare una singola porta
def scan_port(target, port):
	try:
		#Creazioe di un socket
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(1)      #Timeout per ogni connessione
		result = s.connect_ex((target, port)) #Tentativo di connessione
		if result == 0:
			print (f"[+] Porta {port} è APERTA su {target}")
		else:
			print (f"[-] Porta {port} è CHIUSA su {target}")
			s.close()
	except Exception as e:
		print (f"Errore nella scansione della porta {port}: {e}")

#Funzione principale per la scansione delle porte
def scan_ports(target, ports):
	print (f"[*] Avvio scansione delle porte su {target}...")
	start_time = time .time()

	for port in ports:
		scan_port(target, port)

	end_time = time .time()
	print (f"[*] Scansione completata in {round(end_time - start_time, 2)} secondi.\n")

#Target e range di porte
targets = ["192.168.1.129" ]
port_range = range(1, 1025) #Scansione porte da 1 a 1024

#Esecuzione della scansione per ogni target
for target in targets:
	scan_ports(target, port_range)

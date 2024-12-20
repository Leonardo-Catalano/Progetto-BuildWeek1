import socket

def sniffer():
	# Crea un socket con lo scopo di catturare pacchetti
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	s.bind(("0.0.0.0", 0))  # Si mette in ascolto su tutte le interfacce di rete
	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  #Includi l'header IP

	print("In attesa di pacchetti ...")
	try:
		while True:
			pacchetto, indirizzo = s.recvfrom(65535) #Ricevi pacchetti di dimensione 65535max
			print(f"Pacchetto ricevuto da: {indirizzo}")
			#print(f"Payload (esadecimale): {pacchetto.hex()[:50]} ... ")  # Mostra i primi 50 caratteri del payload
	except KeyboardInterrupt:
		print("\nSniffer interrotto.")
	finally:
		s.close()

if __name__ == "__main__":
	sniffer()
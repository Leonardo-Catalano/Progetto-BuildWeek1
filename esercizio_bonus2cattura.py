from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP

#Funzione per filtrare e analizzare tutti i pacchetti
def packet_callback(packet):
	if IP in packet:
		src_ip = packet[IP].src
		dst_ip = packet[IP].dst
		proto = packet[IP].proto
	if TCP in packet:
		protocol = "TCP"
		src_port = packet[TCP].sport
		dst_port = packet[TCP].dport
	elif UDP in packet:
		protocol = "UDP"
		src_port = packet[UPD].sport
		dst_port = packet[UPD].dport
	elif ICMP in packet:
		protocol = "ICMP"
		src_port =  "-"
		dst_port = "-"
	else:
		protocol = "Other"
		src_port = "-"
		dst_port = "-"

	print (f"[{protocol}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

#Funzione principale
def capture_traffic(interface, protocol_filter, output_file):
	print (f"Inizio cattura pacchetti su {interface}, filtro: {protocol_filter}")
	try:
		#Cattura pacchetti con filtro protocollo
		packets = sniff(
			iface=interface,
			filter=protocol_filter,
			prn=packet_callback,
			store=True
		)
		#Salvataggio in file .pcap
		wrpcap(output_file, packets)
		print (f"Pacchetti salvati in {output_file}")
	except KeyboardInterrupt:
		print ("\nCattura interrotta dall'utente.")
	except Exception as e:
		print (f"Errore: {e}")

if __name__ == "__main__":
	#Input utente
	interface = input("Inserisci l'interfaccia di rete (eth0): ")
	protocol = input("Inserisci il protocollo da filtrare ()tcp,udp,icmp o lascia vuoto  per tutti): ")
	output_file = input("Inserisci il nome del file .pcap per salvare i pacchetti (es. uotput.pcap): ")

	#Esegui cattura
	capture_traffic(interface, protocol, output_file)

import scapy.all as scapy
import time
import random


TARGET_IP = "127.0.0.1"  


NUM_SYN_PACKETS = 200

NUM_ICMP_PACKETS = 100


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389, 8080]




def simulate_syn_scan(target_ip, num_packets):
    print(
        f"\nIniciando simulação de SYN Scan em {target_ip} ({num_packets} pacotes)...")
    for _ in range(num_packets):
        ip_layer = scapy.IP(
            dst=target_ip, src=f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}")

        tcp_layer = scapy.TCP(dport=random.choice(
            COMMON_PORTS), flags="S", sport=random.randint(1024, 65535))

        packet = ip_layer / tcp_layer

        scapy.send(packet, verbose=0)
        time.sleep(0.01)  
    print("Simulação de SYN Scan concluída.")



def simulate_icmp_flood(target_ip, num_packets):
    print(
        f"\nIniciando simulação de ICMP Flood em {target_ip} ({num_packets} pacotes)...")
    for _ in range(num_packets):
        ip_layer = scapy.IP(
            dst=target_ip, src=f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}")

        icmp_layer = scapy.ICMP()

        packet = ip_layer / icmp_layer

        scapy.send(packet, verbose=0)
        time.sleep(0.01)
    print("Simulação de ICMP Flood concluída.")



if __name__ == "__main__":
    print("Preparando simulações de ataque...")
    time.sleep(2)  


    simulate_syn_scan(TARGET_IP, NUM_SYN_PACKETS)
    time.sleep(5)  


    simulate_icmp_flood(TARGET_IP, NUM_ICMP_PACKETS)

    print("\nSimulações de ataque enviadas. Verifique o dashboard do IDS.")

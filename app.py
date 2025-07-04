import streamlit as st
import pandas as pd
import time
import threading
import scapy.all as scapy
from collections import deque 
import queue 
import matplotlib.pyplot as plt
import traceback


from ml_utils import get_model, get_scaler, get_feature_columns, predict_packet, MODELS_DIR
from packet_processor import extract_features_from_packet, NUMERIC_COLS_TRAINED


st.set_page_config(
    layout="wide", page_title="IDS em Tempo Real", page_icon="🕵️‍♂️")
st.title("🕵️‍♂️ Sistema de Detecção de Intrusos em Rede (IDS)")
st.markdown(
    "Monitoramento e Classificação de Tráfego em Tempo Real com Machine Learning")


if 'running' not in st.session_state:
    st.session_state.running = False
if 'alerts' not in st.session_state:
    st.session_state.alerts = deque(maxlen=50)
if 'packet_count' not in st.session_state:
    st.session_state.packet_count = 0
if 'normal_count' not in st.session_state:
    st.session_state.normal_count = 0
if 'attack_count' not in st.session_state:
    st.session_state.attack_count = 0
if 'last_update' not in st.session_state:
    st.session_state.last_update = time.time()


_packet_queue = queue.Queue()



def packet_callback(pkt):
    print(
        f"DEBUG: Pacote capturado e callback chamado! Camada IP: {pkt.haslayer(scapy.IP)}")
    if not pkt.haslayer(scapy.IP):
        return

    try:
        processed_df = extract_features_from_packet(pkt)

 
        prediction = predict_packet(processed_df)
        
        packet_data = {
            "prediction": prediction,
            "source_ip": pkt[scapy.IP].src,
            "destination_ip": pkt[scapy.IP].dst,
            "protocol": pkt[scapy.IP].proto,
            "packet_length": len(pkt),
        }

        _packet_queue.put(packet_data)

    except Exception as e:
        print(f"Erro ao processar pacote no callback: {e}")
        pass  



_sniffer_thread = None

_stop_sniffing_flag = threading.Event()

INTERFACES_TO_SNIFF = ['Ethernet 2', '\\Device\\NPF_Loopback']



def start_sniffing():
    print("DEBUG: Botão 'Iniciar Monitoramento' clicado, iniciando sniffing...")
    global _sniffer_thread
    st.session_state.running = True
    _stop_sniffing_flag.clear()  
    st.toast("Monitoramento iniciado!", icon="✅")

    print(
        f"DEBUG: Configurando sniffer na(s) interface(s): {INTERFACES_TO_SNIFF}")
    print("DEBUG: Criando thread para scapy.sniff...")


    def sniff_target():
        try:

            print("Sniffer thread: Tentando iniciar captura...")
            scapy.sniff(
                prn=packet_callback,
                store=0,
                stop_filter=lambda p: _stop_sniffing_flag.is_set(),
                filter="ip",     
                iface=INTERFACES_TO_SNIFF,  
                timeout=None     
            )

            print("Sniffer thread: scapy.sniff retornou.")
        except Exception as e:
            print(f"Sniffer thread: ERRO CRÍTICO na captura: {e}")
            traceback.print_exc()  
        finally:
            print("Sniffer thread encerrada.")
    _sniffer_thread = threading.Thread(target=sniff_target)
    _sniffer_thread.daemon = True

    print("DEBUG: Iniciando thread do sniffer...")
    _sniffer_thread.start()
    print("DEBUG: Thread do sniffer iniciada, esperando pacotes...")


def stop_sniffing():
    st.session_state.running = False
    _stop_sniffing_flag.set() 
    st.toast("Monitoramento parado.", icon="🛑")


    if _sniffer_thread and _sniffer_thread.is_alive():
        _sniffer_thread.join(timeout=5)  
        if _sniffer_thread.is_alive():
            print("Aviso: Thread do sniffer ainda ativa após timeout.")

    st.session_state.packet_count = 0
    st.session_state.normal_count = 0
    st.session_state.attack_count = 0
    st.session_state.alerts.clear()
  
    with _packet_queue.mutex: 
        _packet_queue.queue.clear()



st.sidebar.header("Controles do Sistema")
col1, col2 = st.sidebar.columns(2)

with col1:
    if st.button("Iniciar Monitoramento", disabled=st.session_state.running):
        start_sniffing()

with col2:
    if st.button("Parar Monitoramento", disabled=not st.session_state.running):
        stop_sniffing()

st.sidebar.markdown(
    f"**Status:** {'🟢 Rodando' if st.session_state.running else '🔴 Parado'}")


st.subheader("Métricas de Tráfego")
total_col, normal_col, attack_col = st.columns(3)

total_placeholder = total_col.empty()
normal_placeholder = normal_col.empty()
attack_placeholder = attack_col.empty()


st.subheader("Distribuição de Tráfego")
chart_placeholder = st.empty()  


st.subheader("Alertas de Intrusão Recentes")

alert_dataframe_placeholder = st.empty()


while True:  
    while not _packet_queue.empty():
        try:
            packet_data = _packet_queue.get_nowait()  

            st.session_state.packet_count += 1
            if packet_data["prediction"] == 1:
                st.session_state.attack_count += 1
                alert_msg = {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "source_ip": packet_data["source_ip"],
                    "destination_ip": packet_data["destination_ip"],
                    "protocol": packet_data["protocol"],
                    "packet_length": packet_data["packet_length"],
                    "status": "🚨 ATAQUE DETECTADO!"
                }
                st.session_state.alerts.appendleft(alert_msg)
            else:
                st.session_state.normal_count += 1

        except queue.Empty:
            break
        except Exception as e:
            print(f"Erro ao processar item da fila: {e}")
            break  


    total_placeholder.metric(
        "Total de Pacotes Processados", st.session_state.packet_count)
    normal_placeholder.metric("Pacotes Normais", st.session_state.normal_count)
    attack_placeholder.metric("Pacotes de Ataque", st.session_state.attack_count,
                              delta=f"{st.session_state.attack_count / st.session_state.packet_count * 100:.2f}% do total" if st.session_state.packet_count > 0 else "0.00%")

    if st.session_state.alerts:
        alerts_df = pd.DataFrame(list(st.session_state.alerts))
        alert_dataframe_placeholder.dataframe(
            alerts_df, use_container_width=True)
    else:
        alert_dataframe_placeholder.info(
            "Nenhum alerta de intrusão detectado ainda.")


    if st.session_state.packet_count > 0 and (time.time() - st.session_state.last_update) > 2:
        st.session_state.last_update = time.time()
        labels = ['Normal', 'Ataque']
        sizes = [st.session_state.normal_count, st.session_state.attack_count]
        colors = ['#4CAF50', '#F44336']

        chart_placeholder.empty()
        if sum(sizes) == 0:
            chart_placeholder.write("Aguardando pacotes para o gráfico...")
        else:
            fig, ax = plt.subplots(figsize=(6, 6))
            ax.pie(sizes, labels=labels, autopct='%1.1f%%',
                   colors=colors, startangle=90)

            ax.axis('equal')
            chart_placeholder.pyplot(fig)
            plt.close(fig)  

    time.sleep(0.1)

 
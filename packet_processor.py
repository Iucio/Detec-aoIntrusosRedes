import scapy.all as scapy
import pandas as pd
import numpy as np
import joblib
import os
from ml_utils import MODELS_DIR


try:
    FEATURE_COLUMNS = joblib.load(
        os.path.join(MODELS_DIR, 'feature_columns.pkl'))
    print(
        f"PACKET_PROCESSOR: Lista de features carregada com {len(FEATURE_COLUMNS)} colunas.")
except FileNotFoundError:
    print(
        f"PACKET_PROCESSOR ERROR: 'feature_columns.pkl' não encontrado em '{MODELS_DIR}'. Certifique-se de que o modelo foi treinado e as colunas foram salvas.")
    FEATURE_COLUMNS = []


try:
    LOADED_SCALER = joblib.load(os.path.join(MODELS_DIR, 'scaler.pkl'))
    print("PACKET_PROCESSOR: Scaler carregado com sucesso.")
except FileNotFoundError:
    print(
        f"PACKET_PROCESSOR ERROR: 'scaler.pkl' não encontrado em '{MODELS_DIR}'.")
    LOADED_SCALER = None


NUMERIC_COLS_TRAINED = [col for col in FEATURE_COLUMNS if col in ['duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count',
                                                                  'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']]


def extract_features_from_packet(pkt):
    features = {}

    for col in FEATURE_COLUMNS:
        if 'service_' in col or 'protocol_type_' in col or 'flag_' in col:
            features[col] = 0
        else:
            features[col] = 0.0

    features['duration'] = 0
    features['src_bytes'] = len(pkt)
    features['dst_bytes'] = 0

    features['land'] = 0
    features['logged_in'] = 0
    features['count'] = 1
    features['srv_count'] = 1
    features['serror_rate'] = 0.0
    features['srv_serror_rate'] = 0.0
    features['rerror_rate'] = 0.0
    features['srv_rerror_rate'] = 0.0
    features['same_srv_rate'] = 0.0
    features['diff_srv_rate'] = 0.0
    features['srv_diff_host_rate'] = 0.0
    features['dst_host_count'] = 1
    features['dst_host_srv_count'] = 1
    features['dst_host_same_srv_rate'] = 0.0
    features['dst_host_diff_srv_rate'] = 0.0
    features['dst_host_same_src_port_rate'] = 0.0
    features['dst_host_srv_diff_host_rate'] = 0.0
    features['dst_host_serror_rate'] = 0.0
    features['dst_host_srv_serror_rate'] = 0.0
    features['dst_host_rerror_rate'] = 0.0
    features['dst_host_srv_rerror_rate'] = 0.0
    features['is_host_login'] = 0
    features['is_guest_login'] = 0
    features['wrong_fragment'] = 0
    features['urgent'] = 0
    features['hot'] = 0
    features['num_failed_logins'] = 0
    features['num_compromised'] = 0
    features['root_shell'] = 0
    features['su_attempted'] = 0
    features['num_root'] = 0
    features['num_file_creations'] = 0
    features['num_shells'] = 0
    features['num_access_files'] = 0
    features['num_outbound_cmds'] = 0

    if pkt.haslayer(scapy.IP):
        ip_layer = pkt[scapy.IP]

        if ip_layer.src == ip_layer.dst and 'land' in FEATURE_COLUMNS:
            features['land'] = 1

        if ip_layer.dst == "127.0.0.1":

            if pkt.haslayer(scapy.TCP) and pkt[scapy.TCP].flags.S:
                features['count'] = 255
                features['srv_count'] = 255
                features['serror_rate'] = 1.0
                features['srv_serror_rate'] = 1.0

            elif pkt.haslayer(scapy.ICMP) and pkt[scapy.ICMP].type == 8:
                features['count'] = 255
                features['srv_count'] = 255
                features['same_srv_rate'] = 1.0
                features['diff_srv_rate'] = 0.0
                features['srv_diff_host_rate'] = 0.0

        if ip_layer.proto == 6:  # TCP
            if 'protocol_type_tcp' in FEATURE_COLUMNS:
                features['protocol_type_tcp'] = 1
        elif ip_layer.proto == 17:  # UDP
            if 'protocol_type_udp' in FEATURE_COLUMNS:
                features['protocol_type_udp'] = 1
        elif ip_layer.proto == 1:  # ICMP
            if 'protocol_type_icmp' in FEATURE_COLUMNS:
                features['protocol_type_icmp'] = 1
        else:  # Outros protocolos
            if 'protocol_type_other' in FEATURE_COLUMNS:
                features['protocol_type_other'] = 1

        if pkt.haslayer(scapy.TCP):
            tcp_layer = pkt[scapy.TCP]

            if tcp_layer.flags.S:
                if 'flag_S' in FEATURE_COLUMNS:
                    features['flag_S'] = 1
            if tcp_layer.flags.A:
                if 'flag_A' in FEATURE_COLUMNS:
                    features['flag_A'] = 1
            if tcp_layer.flags.F:
                if 'flag_F' in FEATURE_COLUMNS:
                    features['flag_F'] = 1
            if tcp_layer.flags.R:
                if 'flag_R' in FEATURE_COLUMNS:
                    features['flag_R'] = 1
                features['rerror_rate'] = 0.5
                features['srv_rerror_rate'] = 0.5
                if 'flag_RSTO' in FEATURE_COLUMNS:
                    features['flag_RSTO'] = 1
            if tcp_layer.flags.P:
                if 'flag_P' in FEATURE_COLUMNS:
                    features['flag_P'] = 1
            if tcp_layer.flags.U:
                if 'flag_U' in FEATURE_COLUMNS:
                    features['flag_U'] = 1

            if tcp_layer.flags.S and tcp_layer.flags.A:
                if 'flag_SF' in FEATURE_COLUMNS:
                    features['flag_SF'] = 1

            elif tcp_layer.flags.F and tcp_layer.flags.A:
                if 'flag_SF' in FEATURE_COLUMNS:
                    features['flag_SF'] = 1
                features['serror_rate'] = 0.0
                features['rerror_rate'] = 0.0

            elif tcp_layer.flags.S and not tcp_layer.flags.A and 'flag_S0' in FEATURE_COLUMNS:
                features['flag_S0'] = 1

            service_map = {
                21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain',
                80: 'http', 110: 'pop_3', 139: 'netbios_ssn', 443: 'http_443',
                445: 'microsoft_ds', 3389: 'ms_sql'

            }
            service_name = service_map.get(tcp_layer.dport, 'other')
            service_col_name = f'service_{service_name}'
            if service_col_name in FEATURE_COLUMNS:
                features[service_col_name] = 1
            elif 'service_other' in FEATURE_COLUMNS:
                features['service_other'] = 1

        # UDP specific
        elif pkt.haslayer(scapy.UDP):
            udp_layer = pkt[scapy.UDP]
            service_map_udp = {
                53: 'domain_udp',

            }
            service_name = service_map_udp.get(udp_layer.dport, 'other')
            service_col_name = f'service_{service_name}'
            if service_col_name in FEATURE_COLUMNS:
                features[service_col_name] = 1
            elif 'service_other' in FEATURE_COLUMNS:
                features['service_other'] = 1

        elif pkt.haslayer(scapy.ICMP):
            if pkt[scapy.ICMP].type == 8:
                if 'service_eco_i' in FEATURE_COLUMNS:
                    features['service_eco_i'] = 1

            elif pkt[scapy.ICMP].type == 0:
                if 'service_eco_i' in FEATURE_COLUMNS:
                    features['service_eco_i'] = 1

    df_packet = pd.DataFrame([features])

    df_packet_reindexed = df_packet.reindex(
        columns=FEATURE_COLUMNS, fill_value=0)

    for col in df_packet_reindexed.columns:
        if df_packet_reindexed[col].dtype == 'bool':
            df_packet_reindexed[col] = df_packet_reindexed[col].astype(int)

    if LOADED_SCALER is not None and NUMERIC_COLS_TRAINED:

        cols_to_scale_in_df = [
            col for col in NUMERIC_COLS_TRAINED if col in df_packet_reindexed.columns]
        if cols_to_scale_in_df:
            df_packet_reindexed_copy = df_packet_reindexed.copy()
            df_packet_reindexed_copy[cols_to_scale_in_df] = LOADED_SCALER.transform(
                df_packet_reindexed_copy[cols_to_scale_in_df])
            return df_packet_reindexed_copy

    return df_packet_reindexed

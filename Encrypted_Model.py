import time
from scapy.all import sniff, IP, TCP
import pandas as pd
from IPython.display import clear_output
import pickle as pkl
from elasticsearch import Elasticsearch
from datetime import datetime
from time import mktime

# Initialize an empty list to store extracted data
data_list = []

# Initialize lists for different features
interval_lis = []
ratio_lis = []
total_length_lis = []
ttl_lis = []

# Dictionary to store session information
session_info = {}

# Dictionary to store packet lengths per session
packet_lengths = {}

# Dictionary to store payload sizes per session
payload_sizes = {}

# Function to calculate statistics for a given column
def calculate_statistics(column_name, data):
    window_size = 10

    # Handling column name case for 'Time_to_live'
    if column_name == 'Time_to_live':
        column_name = 'time_to_live'

    # Define column names
    mean_col = f'mean_{column_name}'
    median_col = f'median_{column_name}'
    max_col = f'max_{column_name}'
    min_col = f'min_{column_name}'
    std_col = f'std_{column_name}'
    var_col = f'var_{column_name}'

    if column_name == 'time_to_live':
        column_name = 'Time_to_live'

    # Check if columns exist, and calculate if not
    if mean_col not in data.columns:
        data[mean_col] = data[column_name].rolling(window=window_size, min_periods=1).mean()

    if median_col not in data.columns:
        data[median_col] = data[column_name].rolling(window=window_size, min_periods=1).median()

    if max_col not in data.columns:
        data[max_col] = data[column_name].rolling(window=window_size, min_periods=1).max()

    if min_col not in data.columns:
        data[min_col] = data[column_name].rolling(window=window_size, min_periods=1).min()

    if std_col not in data.columns:
        data[std_col] = data[column_name].rolling(window=window_size, min_periods=1).std()

    if var_col not in data.columns:
        data[var_col] = data[column_name].rolling(window=window_size, min_periods=1).var()

# Callback function to process each captured packet for various features
def packet_callback(packet):
    if IP and TCP in packet:
        # Extract features
        features = {
            'Traffic_sequence': packet[IP].id,
            'Payload_ratio': len(packet[IP].payload) / len(packet),
            'Length_of_IP_packets': len(packet),
            'Length_of_TCP_payload': len(packet[IP].payload),
            'Length_of_TCP_packet_header': len(packet[IP].payload) - len(packet[IP].payload.payload),
            'Length_of_IP_packet_header': len(packet[IP]) - len(packet[IP].payload),
            'TCP_windows_size_value': packet[TCP].window,
            'Length_of_TCP_segment(packet)': len(packet[TCP].payload),
            'Time_difference_between_packets_per_session': time.time() - packet.time,
            'Time_to_live': packet[IP].ttl,
            'timestamp':mktime(datetime.now().timetuple())
        }
        data_list.append(features)

        # Process interval
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        timestamp = time.time()

        interval = timestamp - packet_callback.last_timestamp.get((src_ip, dst_ip), timestamp)
        packet_callback.last_timestamp[(src_ip, dst_ip)] = timestamp
        interval_lis.append(interval)

        # Process ratio
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        current_payload_length = len(packet[IP].payload)

        session_key = (src_ip, dst_ip)

        if session_key in packet_callback.session_info:
            previous_payload_length = packet_callback.session_info[session_key]['previous_payload_length']

            if previous_payload_length > 0:
                ratio = current_payload_length / previous_payload_length
                ratio_lis.append(ratio)

            packet_callback.session_info[session_key]['previous_payload_length'] = current_payload_length
        else:
            packet_callback.session_info[session_key] = {'previous_payload_length': len(packet[IP].payload)}

        # Process total length
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        length = len(packet)

        session_key = f"{src_ip}-{dst_ip}"

        if session_key in packet_callback.packet_lengths:
            packet_callback.packet_lengths[session_key] += length
        else:
            packet_callback.packet_lengths[session_key] = length

        total_length_lis.append(packet_callback.packet_lengths[session_key])

        # Process TTL
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ttl = packet[IP].ttl

        session_key = (src_ip, dst_ip)

        if session_key in packet_callback.sessions:
            packet_callback.sessions[session_key]['Total_Time_to_live_per_session'] += ttl
        else:
            packet_callback.sessions[session_key] = {'Total_Time_to_live_per_session': ttl}

        ttl_lis.append(ttl)

# Initialize a dictionary to store the last timestamp for each source-destination pair
packet_callback.last_timestamp = {}

# Initialize a dictionary to store session information
packet_callback.session_info = {}

# Initialize a dictionary to store packet lengths per session
packet_callback.packet_lengths = {}

# Initialize a dictionary to store session information for TTL
packet_callback.sessions = {}

try:
    es = Elasticsearch("http://192.168.196.98:9200")
except Exception as e:
    raise Exception(e)

# Start capturing live traffic indefinitely
    # Use a single sniff call for efficiency
while True:
  try:
    print("start sniffing")
    sniff(prn=packet_callback, store=0, count=100)
    # Create a DataFrame from the extracted data
    print("sniffing completed")
    data = pd.DataFrame(data_list)
   
    data['Interval_of_arrival_time_of_forward_traffic'] = pd.DataFrame({'Interval_of_arrival_time_of_forward_traffic': interval_lis})
    data['Ratio_to_previous_packets_in_each_session'] = pd.DataFrame({'Ratio_to_previous_packets_in_each_session': ratio_lis})
    data['Total_length_of_IP_packet_per_session'] = pd.DataFrame({'Total_length_of_IP_packet_per_session': total_length_lis})
    data['Total_Time_to_live_per_session'] = pd.DataFrame({'Total_Time_to_live_per_session': ttl_lis})
    #print(data.head())
    # Apply statistics calculation to each feature
    # List of features
    feature = [
    "Length_of_IP_packets",
    "Length_of_TCP_payload",
    "Length_of_TCP_packet_header",
    "Length_of_IP_packet_header",
    "TCP_windows_size_value",
    "Length_of_TCP_segment(packet)",
    "Time_difference_between_packets_per_session",
    "Interval_of_arrival_time_of_forward_traffic",
    "Time_to_live"
      ]
    for i in feature:
        calculate_statistics(i, data)

    # Define desired columns
    desired_columns = [
        'timestamp',
        'Traffic_sequence',
        'Payload_ratio',
        'Length_of_IP_packets',
        'Length_of_TCP_payload',
        'Length_of_TCP_packet_header',
        'Length_of_IP_packet_header',
        'TCP_windows_size_value',
        'Length_of_TCP_segment(packet)',
        'Time_difference_between_packets_per_session',
        'Interval_of_arrival_time_of_forward_traffic',
        'Time_to_live',
        'Ratio_to_previous_packets_in_each_session',
        'Total_length_of_IP_packet_per_session',
        'Total_Time_to_live_per_session',
        'mean_Length_of_IP_packets',
        'median_Length_of_IP_packets',
        'max_Length_of_IP_packets',
        'min_Length_of_IP_packets',
        'std_Length_of_IP_packets',
        'var_Length_of_IP_packets',
        'mean_Length_of_TCP_payload',
        'median_Length_of_TCP_payload',
        'max_Length_of_TCP_payload',
        'min_Length_of_TCP_payload',
        'std_Length_of_TCP_payload',
        'var_Length_of_TCP_payload',
        'mean_Length_of_TCP_packet_header',
        'median_Length_of_TCP_packet_header',
        'max_Length_of_TCP_packet_header',
        'min_Length_of_TCP_packet_header',
        'std_Length_of_TCP_packet_header',
        'var_Length_of_TCP_packet_header',
        'mean_Length_of_IP_packet_header',
        'median_Length_of_IP_packet_header',
        'max_Length_of_IP_packet_header',
        'min_Length_of_IP_packet_header',
        'std_Length_of_IP_packet_header',
        'var_Length_of_IP_packet_header',
        'mean_TCP_windows_size_value',
        'median_TCP_windows_size_value',
        'max_TCP_windows_size_value',
        'min_TCP_windows_size_value',
        'std_TCP_windows_size_value',
        'var_TCP_windows_size_value',
        'mean_Length_of_TCP_segment(packet)',
        'median_Length_of_TCP_segment(packet)',
        'max_Length_of_TCP_segment(packet)',
        'min_Length_of_TCP_segment(packet)',
        'std_Length_of_TCP_segment(packet)',
        'var_Length_of_TCP_segment(packet)',
        'mean_Time_difference_between_packets_per_session',
        'median_Time_difference_between_packets_per_session',
        'max_Time_difference_between_packets_per_session',
        'min_Time_difference_between_packets_per_session',
        'std_Time_difference_between_packets_per_session',
        'var_Time_difference_between_packets_per_session',
        'mean_Interval_of_arrival_time_of_forward_traffic',
        'median_Interval_of_arrival_time_of_forward_traffic',
        'max_Interval_of_arrival_time_of_forward_traffic',
        'min_Interval_of_arrival_time_of_forward_traffic',
        'std_Interval_of_arrival_time_of_forward_traffic',
        'var_Interval_of_arrival_time_of_forward_traffic',
        'mean_time_to_live',
        'median_time_to_live',
        'max_time_to_live',
        'min_time_to_live',
        'std_time_to_live',
        'var_time_to_live',
      ]

    # Filter data with desired columns
    data = data[desired_columns]

    print('Model Loading....')
    filename = 'Encrypted_Model.sav'
    loaded_model = pkl.load(open(filename, 'rb'))
    y_predict = loaded_model.predict(data)
    data['attack'] = y_predict
    #_time = mktime(datetime.now().timetuple())
    #data['timestamp'] = _time
    data = data.astype(str)

    records = data.to_dict(orient='records')
    
    for record in records:
        if record["attack"] == "1":
            es.index(index="encrypted-attack-alerts", document=record)
            # print(record)

    # print('Model prediction Completed')
    # print(data['attack'].value_counts())
    # data.to_csv('/content/drive/MyDrive/Encrypted/encryptedattack.csv')
    # clear_output(wait=True)
  except Exception as e:
    print(f"An error occurred: {e}")
    data = data.iloc[0:0]

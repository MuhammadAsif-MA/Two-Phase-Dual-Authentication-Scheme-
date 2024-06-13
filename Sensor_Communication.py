import time
import threading
import random
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
import os
import pandas as pd
from datetime import datetime

# Static MAC addresses for the sensors
STATIC_MAC_ADDRESSES = ["00:0A:E6:3E:FD:E1", "00:0A:E6:3E:FD:E2", "00:0A:E6:3E:FD:E3", "00:0A:E6:3E:FD:E4", "00:0A:E6:3E:FD:E5"]

# Sensor-side DataFrame for logging
sensor_data_df = pd.DataFrame(columns=['Encryption Time (ms)', 'Sending Time (ms)', 'Payload Size (bits)', 'Packet Count'])

def get_public_key_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

def load_public_key_from_bytes(public_key_bytes):
    return ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), public_key_bytes
    )

def encrypt_data(data, shared_secret):
    key = shared_secret[:32]
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    ct = aesgcm.encrypt(iv, data, None)
    return iv + ct

def log_sensor_data(encryption_time_ms, sending_time_ms, payload_size_bits):
    global sensor_data_df
    new_row = {'Encryption Time (ms)': encryption_time_ms,
               'Sending Time (ms)': sending_time_ms,
               'Payload Size (bits)': payload_size_bits,
               'Packet Count': 1}
    sensor_data_df = pd.concat([sensor_data_df, pd.DataFrame([new_row])], ignore_index=True)

def send_medical_data(client, sensor_mac_address, unique_id, shared_secret):
    while True:
        start_encryption_time = time.perf_counter()
        medical_data = {
            "blood_pressure": random.randint(80, 120),
            "heart_rate": random.randint(60, 100),
            "mac_address": sensor_mac_address
        }
        medical_data_bytes = json.dumps(medical_data).encode()
        encrypted_data = encrypt_data(medical_data_bytes, shared_secret)
        encryption_time_ms = (time.perf_counter() - start_encryption_time) * 1000

        payload_size_bits = len(encrypted_data) * 8
        sending_time_ms = datetime.now().strftime("%H:%M:%S.%f")
        
        # Log the data
        log_sensor_data(encryption_time_ms, sending_time_ms, payload_size_bits)

        sending_time = datetime.now().isoformat()  # ISO 8601 format
        payload = f"{unique_id}|{sending_time}|" + encrypted_data.hex()
        client.publish("medical_data", payload)

        time.sleep(5)  # Adjust the interval as needed

        # Periodically save DataFrame to Excel
        sensor_data_df.to_excel('sensor_data.xlsx', index=False)

def send_public_key(client, mac_address, public_key):
    public_key_data = get_public_key_bytes(public_key).hex()
    client.publish("public_keys/sensors", f"{mac_address}|{public_key_data}", qos=1)
    print(f"Sensor {mac_address} published its public key.")

def send_registration_request(client, mac_address):
    client.publish("registration_request", mac_address)
    print(f"Sensor {mac_address} sent registration request.")

def run_sensor(sensor_mac_address):
    print(f"Starting sensor with MAC address: {sensor_mac_address}")
    curve = ec.SECP256R1()
    my_private_key = ec.generate_private_key(curve)
    my_public_key = my_private_key.public_key()

    sensor_client = mqtt.Client(f"sensor_client_{sensor_mac_address}")
    shared_secret = None
    my_unique_id = None

    def on_connect(client, userdata, flags, rc):
        print(f"Sensor {sensor_mac_address} connected with result code {rc}")
        client.subscribe("public_keys/server")
        client.subscribe(f"registration_response/{sensor_mac_address}")

    def on_message(client, userdata, message):
        nonlocal shared_secret, my_unique_id
        print(f"Sensor {sensor_mac_address} received a message on topic {message.topic}")
        if message.topic == "public_keys/server":
            server_mac, server_public_key_data = message.payload.decode().split('|', 1)
            server_public_key = load_public_key_from_bytes(bytes.fromhex(server_public_key_data))
            shared_secret = my_private_key.exchange(ec.ECDH(), server_public_key)
            send_public_key(client, sensor_mac_address, my_public_key)
            send_registration_request(client, sensor_mac_address)
        elif message.topic == f"registration_response/{sensor_mac_address}":
            my_unique_id = message.payload.decode()
            print(f"Sensor {sensor_mac_address} registered with unique ID: {my_unique_id}")
            threading.Thread(target=send_medical_data, args=(client, sensor_mac_address, my_unique_id, shared_secret)).start()

    sensor_client.on_connect = on_connect
    sensor_client.on_message = on_message
    sensor_client.connect("localhost", 1883)
    sensor_client.loop_start()

    time.sleep(50)  # Adjust as needed to keep the client running
    sensor_client.disconnect()
    sensor_client.loop_stop()

# Starting Threads for Each Sensor
threads = []
for mac in STATIC_MAC_ADDRESSES:
    sensor_thread = threading.Thread(target=run_sensor, args=(mac,))
    sensor_thread.start()
    threads.append(sensor_thread)
    time.sleep(2) # Staggering sensor connections

# Waiting for all threads to complete
for thread in threads:
    thread.join()
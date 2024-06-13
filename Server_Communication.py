import time
import pandas as pd
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
import random
from datetime import datetime

# Server-side DataFrame for logging
server_data_df = pd.DataFrame(columns=['Decryption Time (ms)', 'Receiving Time (ms)', 'Payload Size Received (bits)', 'Packet Count', 'Latency (ms)'])

def generate_random_mac():
    return ':'.join([''.join(random.choices('0123456789ABCDEF', k=2)) for _ in range(6)])

def get_public_key_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

def load_public_key_from_bytes(public_key_bytes):
    return ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), public_key_bytes
    )

def derive_shared_secret(private_key, other_public_key):
    return private_key.exchange(ec.ECDH(), other_public_key)

def decrypt_data(encrypted_data, shared_secret):
    key = shared_secret[:32]
    aesgcm = AESGCM(key)
    iv = encrypted_data[:12]
    ct = encrypted_data[12:]
    try:
        return json.loads(aesgcm.decrypt(iv, ct, None).decode())
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

def log_server_data(decryption_time_ms, receiving_time_ms, payload_size_received_bits, latency_ms):
    global server_data_df
    new_row = {
        'Decryption Time (ms)': decryption_time_ms,
        'Receiving Time (ms)': receiving_time_ms,
        'Payload Size Received (bits)': payload_size_received_bits,
        'Packet Count': 1,
        'Latency (ms)': latency_ms
    }
    server_data_df = pd.concat([server_data_df, pd.DataFrame([new_row])], ignore_index=True)

def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))
    client.subscribe("public_keys/sensors")
    client.subscribe("registration_request")
    client.subscribe("medical_data")

def on_message(client, userdata, message):
    global server_data_df, registered_count, medical_data_df
    print(f"Server received a message on topic {message.topic}")

    if message.topic == "public_keys/sensors":
        mac_address, public_key_data = message.payload.decode().split('|', 1)
        sensor_public_key = load_public_key_from_bytes(bytes.fromhex(public_key_data))
        shared_secret = derive_shared_secret(server_private_key, sensor_public_key)
        sensor_public_keys[mac_address] = {'public_key': public_key_data, 'shared_secret': shared_secret}
        print(f"Processed public key for sensor {mac_address}")

    elif message.topic == "registration_request":
        mac_address = message.payload.decode()
        if mac_address in sensor_public_keys:
            user_input = input(f"Received registration request from {mac_address}. Register this device? (y/n): ")
            if user_input.lower() == 'y':
                registered_count += 1
                unique_id = f"SN{registered_count:04d}"
                legitimate_devices[mac_address] = {'shared_secret': sensor_public_keys[mac_address]['shared_secret'], 'unique_id': unique_id}
                client.publish(f"registration_response/{mac_address}", unique_id)
                print(f"Registered sensor {mac_address} with unique ID {unique_id}")
            else:
                blacklist_devices[mac_address] = "Denied"
                print(f"Blacklisted sensor {mac_address}")
        else:
            print(f"Registration request from unknown sensor {mac_address}")

    elif message.topic == "medical_data":
        receiving_time = datetime.now()
        unique_id, sending_time_str, encrypted_data_hex = message.payload.decode().split('|', 2)
        sending_time = datetime.fromisoformat(sending_time_str)

        # Calculating latency
        latency_ms = (receiving_time - sending_time).total_seconds() * 1000

        device_mac = next((mac for mac, info in legitimate_devices.items() if info['unique_id'] == unique_id), None)
        
        if device_mac:
            shared_secret = legitimate_devices[device_mac]['shared_secret']
            start_decryption_time = time.perf_counter()
            decrypted_data = decrypt_data(bytes.fromhex(encrypted_data_hex), shared_secret)
            decryption_time_ms = (time.perf_counter() - start_decryption_time) * 1000
            payload_size_received_bits = len(bytes.fromhex(encrypted_data_hex)) * 8
            log_server_data(decryption_time_ms, receiving_time.strftime("%H:%M:%S.%f"), payload_size_received_bits, latency_ms)

            if decrypted_data:
                print(f"Decrypted medical data from {unique_id}: {decrypted_data}")
                new_row = {
                    'Unique ID': unique_id,
                    'Blood Pressure': decrypted_data['blood_pressure'],
                    'Heart Rate': decrypted_data['heart_rate'],
                    'MAC Address': decrypted_data['mac_address'],
                    'Timestamp': pd.Timestamp.now()
                }
                medical_data_df = pd.concat([medical_data_df, pd.DataFrame([new_row])], ignore_index=True)
                medical_data_df.to_excel('medical_data.xlsx', index=False)
            else:
                print(f"Failed to decrypt data from {unique_id}")
        else:
            print(f"Received data from unknown or unregistered device with Unique ID: {unique_id}")

# Global variables
broker_address = "localhost"
broker_port = 1883
server_pub_key_topic = "public_keys/server"
sensor_pub_key_topic = "public_keys/sensors"
registration_request_topic = "registration_request"
medical_data_topic = "medical_data"
medical_data_df = pd.DataFrame(columns=['Unique ID', 'Blood Pressure', 'Heart Rate', 'MAC Address', 'Timestamp'])

curve = ec.SECP256R1()
server_private_key = ec.generate_private_key(curve)
server_public_key = server_private_key.public_key()
server_mac_address = generate_random_mac()

sensor_public_keys = {}
registered_count = 0
legitimate_devices = {}
blacklist_devices = {}

server_client = mqtt.Client("server_client_unique_id")
server_client.on_connect = on_connect
server_client.on_message = on_message
server_client.connect(broker_address, broker_port)
server_client.loop_start()

public_key_data = get_public_key_bytes(server_public_key).hex()
server_client.publish(server_pub_key_topic, f"{server_mac_address}|{public_key_data}", qos=2, retain=True)

# Main loop and Cleanup
try:
    time.sleep(70)  # Adjust duration as needed
except KeyboardInterrupt:
    print("Server is shutting down.")
    server_data_df.to_excel('server_data1.xlsx', index=False)  # Save DataFrame to Excel

server_client.disconnect()
server_client.loop_stop()

# Displaying Registered and Blacklisted Devices
print("\nLegitimate Device List:")
for mac, info in legitimate_devices.items():
    print(f"MAC: {mac}, Unique ID: {info['unique_id']}, Shared Secret: {info['shared_secret'].hex()}")

print("\nBlacklisted Device List:")
for mac, status in blacklist_devices.items():
    print(f"MAC: {mac}, Status: {status}")

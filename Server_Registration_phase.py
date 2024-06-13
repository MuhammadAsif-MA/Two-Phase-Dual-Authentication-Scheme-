import time
import random
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

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

def print_server_public_key_pem(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("Server's Public Key in PEM Format:\n", pem.decode())

broker_address = "localhost"
broker_port = 1883
server_pub_key_topic = "public_keys/server"
sensor_pub_key_topic = "public_keys/sensors"
registration_request_topic = "registration_request"

curve = ec.SECP256R1()
server_private_key = ec.generate_private_key(curve)
server_public_key = server_private_key.public_key()
server_mac_address = generate_random_mac()

server_client = mqtt.Client("server_client_unique_id")
sensor_public_keys = {}
registered_count = 0
legitimate_devices = {}

def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))
    client.subscribe(sensor_pub_key_topic)
    client.subscribe(registration_request_topic)

def on_message(client, userdata, message):
    if message.topic == sensor_pub_key_topic:
        mac_address, public_key_data = message.payload.decode().split('|', 1)
        sensor_public_key = load_public_key_from_bytes(bytes.fromhex(public_key_data))
        shared_secret = derive_shared_secret(server_private_key, sensor_public_key)
        sensor_public_keys[mac_address] = {'public_key': public_key_data, 'shared_secret': shared_secret}
        print(f"Server derived shared secret with sensor {mac_address}: {shared_secret.hex()}")
    elif message.topic == registration_request_topic:
        mac_address = message.payload.decode()
        if mac_address in sensor_public_keys:
            user_input = input(f"Received registration request from {mac_address}. Register this device? (y/n): ")
            if user_input.lower() == 'y':
                global registered_count
                registered_count += 1
                unique_id = f"SN{registered_count:04d}"
                legitimate_devices[mac_address] = {'shared_secret': sensor_public_keys[mac_address]['shared_secret'], 'unique_id': unique_id}
                client.publish(f"registration_response/{mac_address}", unique_id)
                print(f"Sensor {mac_address} registered with unique ID: {unique_id}")
            else:
                print(f"Registration request from {mac_address} denied.")

server_client.on_connect = on_connect
server_client.on_message = on_message
server_client.connect(broker_address, broker_port)
server_client.loop_start()

public_key_data = get_public_key_bytes(server_public_key).hex()
server_client.publish(server_pub_key_topic, f"{server_mac_address}|{public_key_data}", qos=2, retain=True)
print(f"Server published its public key.")

# Print the server's public key in PEM format
print_server_public_key_pem(server_public_key)

time.sleep(100)

server_client.disconnect()
server_client.loop_stop()

print("Legitimate Device List:")
for mac, info in legitimate_devices.items():
    print(f"MAC: {mac}, Unique ID: {info['unique_id']}, Shared Secret: {info['shared_secret'].hex()}")
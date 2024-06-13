import time
import threading
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Define a list of static MAC addresses for the sensors
STATIC_MAC_ADDRESSES = ["00:0A:E6:3E:FD:E1", "00:0A:E6:3E:FD:E2", "00:0A:E6:3E:FD:E3", "00:0A:E6:3E:FD:E4", "00:0A:E6:3E:FD:E5"]

def get_public_key_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

def load_public_key_from_bytes(public_key_bytes):
    return ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), public_key_bytes
    )

def run_sensor(sensor_mac_address):
    curve = ec.SECP256R1()
    my_private_key = ec.generate_private_key(curve)
    my_public_key = my_private_key.public_key()
    my_mac_address = sensor_mac_address  # Use the provided static MAC address

    sensor_client = mqtt.Client(f"sensor_client_{my_mac_address}")

    def on_connect(client, userdata, flags, rc):
        print(f"Sensor {my_mac_address} connected with result code {rc}")
        if rc == 0:
            client.subscribe("public_keys/server", qos=2)
            client.subscribe(f"registration_response/{my_mac_address}")

    def on_message(client, userdata, message):
        topic, payload = message.topic, message.payload.decode()
        if topic == "public_keys/server":
            server_mac, server_public_key_data = payload.split('|', 1)
            server_public_key = load_public_key_from_bytes(bytes.fromhex(server_public_key_data))
            shared_secret = my_private_key.exchange(ec.ECDH(), server_public_key)
            print(f"Sensor {my_mac_address} derived shared secret: {shared_secret.hex()}")
            time.sleep(4)
            send_registration_request(client)
        elif topic == f"registration_response/{my_mac_address}":
            unique_id = payload
            print(f"Sensor {my_mac_address} registered with unique ID: {unique_id}")

    def send_registration_request(client):
        client.publish("registration_request", my_mac_address)
        print(f"Sensor {my_mac_address} sent registration request.")

    sensor_client.on_connect = on_connect
    sensor_client.on_message = on_message

    sensor_client.connect("localhost", 1883)
    sensor_client.loop_start()

    public_key_data = get_public_key_bytes(my_public_key).hex()
    sensor_client.publish("public_keys/sensors", f"{my_mac_address}|{public_key_data}", qos=1)
    print(f"Sensor {my_mac_address} published its public key.")

    time.sleep(150)

    sensor_client.disconnect()
    sensor_client.loop_stop()

# Create and start a thread for each sensor with a unique MAC address
threads = []
for mac in STATIC_MAC_ADDRESSES:
    sensor_thread = threading.Thread(target=run_sensor, args=(mac,))
    sensor_thread.start()
    threads.append(sensor_thread)
    time.sleep(2)  # Staggering sensor connections

for thread in threads:
    thread.join()
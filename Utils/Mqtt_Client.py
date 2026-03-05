import paho.mqtt.client as mqtt
import json

class MQTTClientWrapper:
    def __init__(self, client_id, broker="localhost", port=1883, #Broker is localhost unless running WireShark where Device's local IP is used
             username=None, password=None,
             use_weak_credentials=True,
             use_unencrypted_traffic=True):

        # Create MQTT client with required API version
        self.client = mqtt.Client(
            client_id=client_id,
            callback_api_version=mqtt.CallbackAPIVersion.VERSION1
        )

        # Vulnerability: Unencrypted MQTT traffic
        self.use_unencrypted_traffic = use_unencrypted_traffic
        if self.use_unencrypted_traffic:
            print("[VULNERABILITY] MQTT traffic is UNENCRYPTED (port 1883)")

        # Vulnerability: Weak / Default credentials
        if use_weak_credentials:
            self.client.username_pw_set("admin", "1234")

        # If normal credentials are explicitly provided
        if username and password and not use_weak_credentials:
            self.client.username_pw_set(username, password)

        # Connect to broker (unencrypted - another vulnerability)
        self.client.connect(broker, port, keepalive=60)
        self.client.loop_start()

    def publish(self, topic, payload):
        msg = json.dumps(payload)
        self.client.publish(topic, msg)

    def stop(self):
        self.client.loop_stop()
        self.client.disconnect()

# Dashboard/app.py

from flask import Flask, app, render_template, request, jsonify
from flask_socketio import SocketIO
import threading

from Mqtt_Listener import start_mqtt_listener, set_socketio


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "change-this-secret-key"

    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading", engineio_logger=True, logger=True, always_connect=True, engineio_protocol=3)


    # Give SocketIO instance to MQTT listener so it can emit events
    set_socketio(socketio)

    @socketio.on("connect")
    def on_connect():
        print("A dashboard client connected")

    @socketio.on("disconnect")
    def on_disconnect():
        print("A dashboard client disconnected")

    @app.route("/")
    def index():
        return render_template("index.html")

    '''
    @app.route("/api/security_event", methods=["POST"])
    def security_event():
        """
        Generic endpoint for other scripts to push security alerts.
        Example JSON body:
        {
            "type": "weak_password_bruteforce",
            "device_id": "TempSensor_1",
            "message": "Bruteforce attempt detected",
            "details": {...}
        }
        """
        data = request.get_json() or {}
        # Broadcast to all connected dashboard clients
        socketio.emit("security_event", data)
        return jsonify({"status": "ok"})
    '''

    @app.route("/api/devices", methods=["GET"])
    def get_devices():
        from Mqtt_Listener import latest_device_data
        return jsonify(latest_device_data)


    @app.route("/api/devices/<device_id>", methods=["GET"])
    def get_device(device_id):
        from Mqtt_Listener import latest_device_data
        if device_id in latest_device_data:
            return jsonify(latest_device_data[device_id])
        return jsonify({"error": "Device not found"}), 404


    @app.route("/api/devices/<device_id>/firmware", methods=["GET"])
    def firmware_check(device_id):
        from Mqtt_Listener import latest_device_data
        if device_id not in latest_device_data:
            return jsonify({"error": "Device not found"}), 404
        
        device = latest_device_data[device_id]
        return jsonify({
            "device_id": device_id,
            "firmware_version": device.get("firmware_version"),
            "latest_firmware_version": device.get("latest_firmware_version"),
            "firmware_outdated": device.get("firmware_outdated")
        })

    @app.route("/insecure/device-info", methods=["GET"])
    def insecure_device_info():
        from Mqtt_Listener import latest_device_data
        return jsonify(latest_device_data)


    @app.route("/api/security_event", methods=["POST"])
    def receive_security_event():
        data = request.json
        socketio.emit("security_event", data)  # Emit to all connected clients
        return jsonify({"status": "received"})

    return app, socketio

def start_mqtt_in_background():
    # Run MQTT listener in a separate daemon thread
    t = threading.Thread(target=start_mqtt_listener, daemon=True)
    t.start()


if __name__ == "__main__":
    app, socketio = create_app()

    # Start MQTT listener thread
    start_mqtt_in_background()

    # Use eventlet for WebSocket support
    # Access dashboard at: http://localhost:5000
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, allow_unsafe_werkzeug=True)

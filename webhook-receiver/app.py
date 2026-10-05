from flask import Flask, request
import json
from datetime import datetime

app = Flask(__name__)
LOG_FILE = "falco_alerts.jsonl"

@app.route('/falco-alerts', methods=['POST'])
def receive_alert():
    data = request.get_json()
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Rule: {data.get('rule')} | Priority: {data.get('priority')}")
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")
    return {"status": "received"}, 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

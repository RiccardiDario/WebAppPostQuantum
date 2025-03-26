from flask import Flask, jsonify, request

app = Flask(__name__)
ready_flag = False

@app.route('/')
def home():
    return jsonify(message="Hello, HTTPS world!")

@app.route('/ready', methods=['POST'])
def set_ready():
    global ready_flag
    ready_flag = True
    return jsonify(status="ready flag set")

@app.route('/status', methods=['GET'])
def get_status():
    return jsonify(ready=ready_flag)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)


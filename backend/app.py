import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from backend.analyzer import analyze_contract
from backend.history.history_manager import HistoryManager
from backend.report_generator import ReportGenerator
from groq_client import get_chat_response

# Load environment variables from .env file
load_dotenv()

# --- Initialize Flask App ---
app = Flask(__name__)
history_manager = HistoryManager()
report_generator = ReportGenerator()
CORS(app)  # Enable Cross-Origin Resource Sharing for the extension

# --- API Endpoints ---

@app.route('/analyze', methods=['POST'])
def analyze_endpoint():
    """Endpoint to analyze a smart contract."""
    data = request.get_json()
    contract_address = data.get('contract_address')
    if not contract_address:
        return jsonify({"error": "Contract address is required."}), 400

    result = analyze_contract(contract_address)

    if isinstance(result, dict) and not result.get("error"):
        try:
            history_manager.save_analysis(result)
        except Exception as history_error:
            print(f"History save warning: {history_error}")

    return jsonify(result)


@app.route('/report', methods=['POST'])
def report_endpoint():
    """Generate a structured JSON security report."""
    data = request.get_json() or {}
    contract_address = data.get('contract_address')

    if not contract_address:
        return jsonify({"error": "Contract address is required."}), 400

    result = analyze_contract(contract_address)

    if isinstance(result, dict) and result.get("error"):
        return jsonify(result), 400

    report_result = report_generator.save_json(result)

    return jsonify({
        "success": True,
        "report_path": report_result["report_path"],
        "report": report_result["report"]
    })


@app.route('/history', methods=['GET'])
def history_endpoint():
    """Return recent analysis history."""
    limit = request.args.get('limit', default=None, type=int)
    return jsonify({
        "success": True,
        "history": history_manager.get_history(limit=limit)
    })


@app.route('/history/<contract_address>', methods=['GET'])
def contract_history_endpoint(contract_address):
    """Return analysis history for a specific contract."""
    limit = request.args.get('limit', default=None, type=int)
    return jsonify({
        "success": True,
        "contract_address": contract_address,
        "history": history_manager.get_contract_history(
            contract_address,
            limit=limit
        )
    })


@app.route('/chat', methods=['POST'])
def chat_endpoint():
    """Endpoint to handle chatbot conversations."""

    data = request.get_json()

    question = data.get('question')
    context = data.get('context')

    if not question or not context:
        return jsonify({"error": "A question and analysis context are required."}), 400

    answer = get_chat_response(question, context)

    return jsonify({"answer": answer})


# --- Run the App ---

if __name__ == '__main__':
    # Running on 0.0.0.0 makes it accessible on your local network
    app.run(host='0.0.0.0', port=5001, debug=True)


from flask import jsonify

def api_response(success, message=None, data=None, errors=None, status_code=200):
    response = {
        'success': success,
        'message': message,
        'data': data,
        'errors': errors
    }
    return jsonify(response), status_code
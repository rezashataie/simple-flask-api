import http.client
import urllib.parse
import logging


def send_sms(receptor, template, params=None):
    try:
        conn = http.client.HTTPSConnection("api.ghasedaksms.com")

        # Build payload with URL-encoded parameters
        payload_data = {
            "type": "1",
            "receptor": receptor,
            "template": template,
        }
        if params:
            for key, value in params.items():
                payload_data[key] = value

        payload = urllib.parse.urlencode(payload_data)
        headers = {
            "apikey": "L2vReSImkXEBUz7bg83EgvGHOX+Q62YfDjcPFh73Su4",
            "content-type": "application/x-www-form-urlencoded",
        }

        # Make the POST request
        conn.request("POST", "/v2/send/verify", payload, headers)
        res = conn.getresponse()
        data = res.read()

        # Decode and return the API response
        response_data = data.decode("utf-8")
        logging.info(f"SMS sent successfully to {receptor} using template {template}")
        return response_data
    except Exception as e:
        logging.error(f"Failed to send SMS to {receptor}: {e}")
        return None

import http.client
import urllib.parse
import logging


class SMSService:
    """
    A service class for managing SMS sending operations.
    """

    API_URL = "api.ghasedaksms.com"
    API_KEY = "L2vReSImkXEBUz7bg83EgvGHOX+Q62YfDjcPFh73Su4"

    @staticmethod
    def send(receptor, template, params=None):
        """
        Send an SMS using the Ghasedak SMS API.
        :param receptor: The recipient's phone number.
        :param template: The template name to use.
        :param params: Optional dictionary of parameters for the template.
        :return: The API response as a string, or None if an error occurred.
        """
        try:
            conn = http.client.HTTPSConnection(SMSService.API_URL)

            # Build payload with URL-encoded parameters
            payload_data = {
                "type": "1",
                "receptor": receptor,
                "template": template,
            }
            if params:
                payload_data.update(params)

            payload = urllib.parse.urlencode(payload_data)
            headers = {
                "apikey": SMSService.API_KEY,
                "content-type": "application/x-www-form-urlencoded",
            }

            # Make the POST request
            conn.request("POST", "/v2/send/verify", payload, headers)
            res = conn.getresponse()
            data = res.read()

            # Decode and return the API response
            response_data = data.decode("utf-8")
            logging.info(
                f"SMS sent successfully to {receptor} using template {template}"
            )
            return response_data
        except Exception as e:
            logging.error(f"Failed to send SMS to {receptor}: {e}")
            return None

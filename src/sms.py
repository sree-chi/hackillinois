from __future__ import annotations

import base64
import logging
import os
from urllib import parse, request


logger = logging.getLogger("SentinelAuth.sms")


class SmsDeliveryError(RuntimeError):
    pass


class SmsSender:
    def __init__(self) -> None:
        self.mode = os.getenv("SMS_DELIVERY_MODE", "mock").strip().lower()

    def send_verification_code(self, phone_number: str, code: str) -> dict[str, str | None]:
        message = f"Your Sentinel Auth verification code is {code}. It expires in 10 minutes."
        if self.mode == "twilio":
            self._send_with_twilio(phone_number, message)
            return {"delivery_channel": "sms", "dev_code": None}

        logger.warning("Mock SMS verification code for %s: %s", phone_number, code)
        return {"delivery_channel": "mock", "dev_code": code}

    def _send_with_twilio(self, phone_number: str, message: str) -> None:
        account_sid = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
        auth_token = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
        from_number = os.getenv("TWILIO_FROM_NUMBER", "").strip()
        if not account_sid or not auth_token or not from_number:
            raise SmsDeliveryError("Twilio delivery requires TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_FROM_NUMBER.")

        body = parse.urlencode(
            {
                "To": phone_number,
                "From": from_number,
                "Body": message,
            }
        ).encode("utf-8")
        req = request.Request(
            f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json",
            data=body,
            method="POST",
            headers={
                "Authorization": "Basic " + base64.b64encode(f"{account_sid}:{auth_token}".encode("utf-8")).decode("ascii"),
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        try:
            with request.urlopen(req, timeout=10) as response:
                if response.status >= 400:
                    raise SmsDeliveryError(f"Twilio SMS delivery failed with status {response.status}.")
        except Exception as exc:
            raise SmsDeliveryError(f"Unable to send verification code: {exc}") from exc

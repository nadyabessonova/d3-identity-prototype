"""Original deterministic detect service kept for gateway compatibility."""


class DetectService:
    action = "detect"
    input_type = "scan_request"
    output_type = "report"
    endpoint = "local://detect"

    def execute(self, payload):
        return {
            "result": "ok",
            "action": self.action,
            "report": {
                "sample": payload.get("sample"),
                "classification": "benign",
                "confidence": 0.98,
            },
        }

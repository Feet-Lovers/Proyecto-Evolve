import json
import redis
from mitmproxy import http

r = redis.Redis(host='redis', port=6379)

class Capture:
    def response(self, flow: http.HTTPFlow):
        data = {
            "id": flow.id,
            "host": flow.request.host,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "status": flow.response.status_code,
            "req_headers": dict(flow.request.headers),
            "res_headers": dict(flow.response.headers),
            "req_body": flow.request.get_text(strict=False),
            "res_body": flow.response.get_text(strict=False),
        }
        r.publish("traffic", json.dumps(data))

addons = [Capture()]

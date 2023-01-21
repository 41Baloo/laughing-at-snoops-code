import iptables
import crypto
import http
import std/http
import std/uri
import time

var requests = 0
var bypassed_requests = 0
# JavaScript challenge
fn js_challenge(req: http.Request) {
    let cookie_name = "js_challenge_passed"
    let cookie_value = crypto.random_string(32)
    let cookie_expiration = time.now() + 30m

    # Set encrypted cookie
    let encrypted_value = crypto.encrypt(cookie_value)
    req.response.set_cookie(cookie_name, encrypted_value, cookie_expiration)

    # Basic button click challenge that everyone uses feel free to make it look prettier 
    req.response.body = """
        <html>
            <body>
                <script>
                    function check_passed() {
                        let cookie_value = getCookie("${cookie_name}");
                        let decrypted_value = decrypt(cookie_value);
                        if (decrypted_value == "${cookie_value}") {
                            window.location.href = "${req.url}";
                        } else {
                            alert("JavaScript challenge failed.");
                        }
                    }
                </script>
                <button onclick="check_passed()">Click me to pass the challenge</button>
            </body>
        </html>
    """
}

fn handle_request(req: http.Request) {
	var query = req.url.query.decode_uri()
	var RCE = ["reboot", "curl", "wget", "bash", "select from", ";", ",", "|"]

	for phrase in RCE {
    	if query.to_lower() == phrase.to_lower() {
                req.respond({
                    status_code: 403,
                    body: "You have been blocked by seclusion",
                })
                return
            }
    }

    # Check if JavaScript challenge has been passed
    let cookie_name = "js_challenge_passed"
    let cookie_value = req.cookies[cookie_name]
    if (cookie_value != null) {
        let decrypted_value = crypto.decrypt(cookie_value)
        if (decrypted_value != null) {
            req.response.status_code = 307
			// does a temporary redirect if the challenge suceeds to your backend server ip
            req.response.headers["Location"] = "http://backend-server" + req.url
            return
        }
    }
	while (true) {
    	requests += 1
    	println("requests per second: ", requests / time.seconds(), " Requested bypassed per second: ", bypassed_requests / time.seconds())

		if req.response.status_code = 200 {
			bypassed_requests += 1
		}
		time.sleep(1)

		# Discord alerts if you really please
		if bypassed_requests > 1000:
			webhook_url = "discord_webhook_goes_here"
    		message = {"content": "We have detected a ddos attack coming in at {} r/s, additional security measures will be enabled.".format(requests)}
    		requests.post(webhook_url, json=message)
	}

    # Serve JavaScript challenge
    js_challenge(req)
}

# Create server
let server = http.create_server(handle_request)
server.listen(80)

import http.cookies as _http_cookies


_http_cookies.Morsel._reserved["samesite"] = "SameSite"

SimpleCookie = _http_cookies.SimpleCookie

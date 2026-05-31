from flask import Flask, request, Response, jsonify
import blackboxprotobuf as pb
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import requests, random, hashlib, json, os, time, threading

app = Flask("gringo.bytes")

key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
iv  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
decrypt = lambda x: unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(x), 16)
encrypt = lambda x: AES.new(key, AES.MODE_CBC, iv).encrypt(pad(x, 16))
sessions = {}
ssl = threading.Lock()

clearx = lambda headers: {k: v for k, v in headers.items() if k.lower() not in {"content-encoding", "content-length", "connection", "transfer-encoding", "host"}}

@app.route("/start", methods=["GET"])
def start():
 access = request.args.get("token", str()).strip()
 if not access: return Response(b"[c][AAFF00]Unauthorized", status=401)

 access_hash = hashlib.md5(access.encode()).hexdigest()
 sid = "".join(str(random.randint(0, 9)) for _ in range(10))
 exp = time.time() + 300
 with ssl:
  sessions[sid] = {"hash": access_hash, "expire": exp, "token": access}
 t=threading.Timer(300, lambda: sessions.pop(sid, None))
 t.daemon = True
 t.start()

 return jsonify({
  "sid": sid,
  "hash": access_hash,
  "exp": time.strftime("%H:%M:%S", time.localtime(exp))
 })


@app.route("/", defaults={"params": ""}, methods=["GET", "POST"])
@app.route("/<path:params>", methods=["GET", "POST"])
def proxy(params):
 try:token, session, endpoint = params.split("auth:")[1].split(":", 2)
 except: return Response(b"Unauthorized!", status=403)

 with ssl:
  ss = sessions.get(session)
 if ss is None or time.time() > ss["expire"]:
  if ss is not None:
   with ssl: sessions.pop(session, None)
  return Response("[AAFF00]Vui lòng đăng kí dịch vụ trên\n [u]Localconfig.LuanOri.Space[/u]\n để tiếp tục sử dụng!".encode("utf-8"), status=200)

 data = request.get_data()
 headers = clearx(dict(request.headers))
 headers["Host"] = "loginbp.ggpolarbear.com"

 try:
  if endpoint == "MajorLogin":
   inspect = requests.get("https://auth.garena.com/oauth/token/inspect?token=%s" % ss["token"]).json()
   if "open_id" not in inspect:
    return Response(b"[FFFF00]ACCOUNT NOT FOUND", status=500)

   try:
    fields, typedef = pb.decode_message(decrypt(data))
    fields["22"]  = str(inspect.get("open_id"))
    fields["23"]  = str(inspect.get("main_active_platform"))
    fields["29"]  = str(ss["token"])
    fields["99"]  = str(inspect.get("platform"))
    fields["100"] = str(inspect.get("login_platform"))
    payload = encrypt(pb.encode_message(fields, typedef))
    response = requests.request(
     method=request.method,
     url="https://loginbp.ggpolarbear.com/%s" % endpoint,
     data=payload, headers=headers)
   except Exception as error:
    return Response("[FFFF00]THỬ LẠI SAU!".encode("utf-8"), status=500)
  else: response = requests.request(method=request.method,
    url="https://loginbp.ggpolarbear.com/%s" % endpoint,
    data=data, headers=headers)

  return Response(
   response.content,
   status=response.status_code,
   headers=clearx(dict(response.headers))
  )

 except requests.exceptions.Timeout: return "", 401
 except requests.exceptions.RequestException as e:
  return Response(str(e).encode(), status=500)


if __name__ == "__main__":
 app.run(host="0.0.0.0", port=2026, threaded=True)

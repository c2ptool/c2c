import pysodium
import binascii
import websocket
import ssl
import json
import array

try:
    import thread
except ImportError:
    import _thread as thread

import time

publickey = binascii.unhexlify(b'34791aba0ffedb596abbbc0b6a44c27b22883d3980777a7d49d62a03f4f8ee41')
secretkey = binascii.unhexlify(b'6d9ef378cc473b8b4bb295291a9bc36f32b342a68da66ea6e2c96fba305cd89834791aba0ffedb596abbbc0b6a44c27b22883d3980777a7d49d62a03f4f8ee41')

get_identify_reply_id = b''
get_identify_reply_tn = b''

remote_node_id = b''

get_reply_id = b''
get_fin_reply_id = b''
call_reply_id = b''

def do_send_get_fin(ws):
    global get_fin_reply_id
    get_fin_reply_id = binascii.hexlify(pysodium.randombytes(16)).decode("utf-8")
    ws.send(json.dumps({"jsonrpc":"2.0","method":"get","id":get_fin_reply_id,"params":["db-0",[0,1,"test-item"]]}))
    print("get-fin")

def do_send_del(ws):
    ws.send(json.dumps({"jsonrpc":"2.0","method":"del","params":["db-0",[0,1,"test-item"]]}))
    print("del")
    for i in range(1):
        time.sleep(1)
        do_send_get_fin(ws)

def do_send_get(ws):
    global get_reply_id
    get_reply_id = binascii.hexlify(pysodium.randombytes(16)).decode("utf-8")
    ws.send(json.dumps({"jsonrpc":"2.0","method":"get","id":get_reply_id,"params":["db-0",[0,1,"test-item"]]}))
    print("get")
    for i in range(1):
        time.sleep(1)
        do_send_del(ws)

def do_send_put(ws):
    ws.send(json.dumps({"jsonrpc":"2.0","method":"put","params":["db-0",[0,1,"test-item"],{"a":1,"b":2,"c":3}]}))
    print("put")
    for i in range(1):
        time.sleep(1)
        do_send_get(ws)

def on_message(ws, data):
    #print("msg: ", data)
    msg = json.loads(data)
    #id = "".join(map(chr, (msg['id'])))
    id = msg['id']
    if id == get_identify_reply_id:
        global remote_node_id

        pk = bytes(msg['result'][0])
        sg = bytes(msg['result'][1])

        remote_node_id = pk

        hex_id = binascii.hexlify(remote_node_id).decode("utf-8")

        try:
            pysodium.crypto_sign_verify_detached(sg, get_identify_reply_tn, pk)
            print("OK!!! node id: ", hex_id)
        except:
            print("error identify node id: ", hex_id)

        do_send_put(ws)
        return

    if id == get_reply_id:
        print("GET result!!!:\n", msg)
        return

    if id == get_fin_reply_id:
        print("GET finally result!!!:\n", msg)
        return

    if msg["method"] == "get_identify":
        tn = bytes(msg['params'][0])
        digest = binascii.unhexlify(b'DAFBABCBC50DF4BB432C72F610878A6990E85734')
        with_digest = msg['params'][1]
        sm = tn
        if with_digest:
            sm.append(digest)
        sg = pysodium.crypto_sign_detached(sm, secretkey)
        ws.send(json.dumps({"jsonrpc":"2.0","id":msg['id'],"result":(list(bytearray(publickey)),list(bytearray(sg)))}))
                

def on_error(ws, error):
    print(error)

def on_close(ws):
    print("### closed ###")

def json_bytes2hex(bin):
    return "".join("\\\\x{:02x}".format(x) for x in bin)

def on_open(ws):
    def run(*args):
        global get_identify_reply_tn
        global get_identify_reply_id
        get_identify_reply_tn = pysodium.randombytes(16)
        get_identify_reply_id = binascii.hexlify(pysodium.randombytes(16)).decode("utf-8")
        for i in range(1):
            time.sleep(1)
            msg = json.dumps({"jsonrpc":"2.0","method":"get_identify","id":get_identify_reply_id,"params":(list(bytearray(get_identify_reply_tn)),False)})
            #print(msg)
            ws.send(msg)
        time.sleep(100)
        print("thread terminating...")
    thread.start_new_thread(run, ())

if __name__ == "__main__":
    websocket.enableTrace(False)
    ws = websocket.WebSocketApp("wss://127.0.0.1:12002",
                              on_message = on_message,
                              on_error = on_error,
                              on_close = on_close,
                              header = ["Sec-WebSocket-Protocol: data"])
    crtpath = "./keys/"
    ws.on_open = on_open
    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_REQUIRED, "check_hostname": False,
                           "ca_certs": crtpath+"ca.pem",
                           "keyfile": crtpath+"localhost.key.pem",
                           "certfile": crtpath+"localhost.crt"})

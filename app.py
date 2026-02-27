from flask import Flask, request, render_template, send_file
import os
import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import zlib

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "outputs"
MODEL_FOLDER = "models"

MODELS = {
    "cover1.png": 10,
    "cover2.png": 15,
    "cover3.png": 18
}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

@app.route("/")
def home():
    return render_template("index.html", models=MODELS)

@app.route("/encrypt", methods=["POST"])
def encrypt_and_embed():

    file = request.files["file"]


    filename = file.filename
    ext = os.path.splitext(filename)[1].encode()

    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    with open(filepath, "rb") as f:
        data = f.read()

    compressed = zlib.compress(data)
    file_size_mb = len(data) / (1024 * 1024)
    recommended = None
    for model, cap in MODELS.items():
        if file_size_mb < cap:
            recommended = model
            break


    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)

    encrypted = aesgcm.encrypt(nonce, compressed, None)

    length = len(nonce + encrypted)
    header = length.to_bytes(4, byteorder="big")

    payload = ext + b"|" + header + nonce + encrypted

    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))

    file_bits = len(bits)
    selected_model = None
    selected_capacity_mb = 0

    for model in MODELS:
        img_test = Image.open("models/" + model).convert("RGB")
        arr_test = np.array(img_test)
        capacity_bits = arr_test.size * 2
        capacity_mb = capacity_bits / 8 / (1024 * 1024)

        if file_bits <= capacity_bits:
            selected_model = model
            selected_capacity_mb = capacity_mb
            break


    if selected_model is None:
        return "<h3>File too large for all available models!</h3>"
    usage_percent = (file_size_mb / selected_capacity_mb) * 100


    img = Image.open("models/" + selected_model).convert("RGB")

    arr = np.array(img)
    flat = arr.flatten()

    capacity = len(flat) * 2

    if len(bits) > capacity:
        return "<h3>File too large for this model!</h3><a href='/'>Back</a>"

    pairs = bits.reshape(-1,2)
    values = pairs[:,0]*2 + pairs[:,1]

    flat[:len(values)] = (flat[:len(values)] & 252) | values
    stego = flat.reshape(arr.shape)

    out_path = os.path.join(OUTPUT_FOLDER, "stego.png")
    Image.fromarray(stego).save(out_path)

    return render_template(
    "success_embed.html",
    model=selected_model,
    key=key.hex(),
    file_size=round(file_size_mb,2),
    capacity=round(selected_capacity_mb,2),
    usage=round(usage_percent,1)
    )




@app.route("/extract", methods=["POST"])
def extract_and_decrypt():

    stego_file = request.files["stego"]
    key_hex = request.form["key"]

    key = bytes.fromhex(key_hex)

    stego_path = os.path.join(UPLOAD_FOLDER, "uploaded_stego.png")
    stego_file.save(stego_path)

    img = Image.open(stego_path).convert("RGB")
    arr = np.array(img).flatten()

    vals = arr & 3
    b1 = vals >> 1
    b2 = vals & 1

    extracted_bits = np.column_stack((b1,b2)).flatten()
    extracted_bytes = np.packbits(extracted_bits)

    raw = extracted_bytes.tobytes()

    sep = raw.find(b"|")
    ext = raw[:sep].decode()

    rest = raw[sep+1:]

    length = int.from_bytes(rest[:4], byteorder="big")
    payload = rest[4:4+length]

    nonce = payload[:12]
    ciphertext = payload[12:]

    aesgcm = AESGCM(key)

    try:
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        original = zlib.decompress(decrypted)
    except:
        return "<h3>Wrong key or corrupted file!</h3><a href='/'>Back</a>"

    out_file = os.path.join(OUTPUT_FOLDER, "recovered" + ext)
    with open(out_file, "wb") as f:
        f.write(original)

    return render_template("success_extract.html")


@app.route("/download_stego")
def download_stego():
    return send_file("outputs/stego.png", as_attachment=True)

@app.route("/download_recovered")
def download_recovered():
    files = os.listdir("outputs")
    recovered = [f for f in files if f.startswith("recovered")]
    if recovered:
        return send_file(os.path.join("outputs", recovered[0]), as_attachment=True)
    return "<h3>No recovered file found</h3>"

if __name__ == "__main__":
    app.run()

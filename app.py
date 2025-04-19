from flask import Flask, render_template, request, send_from_directory, redirect
import os
from werkzeug.exceptions import RequestEntityTooLarge

# -------------------- MODULE IMPORTS --------------------
from modules.ctf_helpers.decoder import decode_text
from modules.ctf_helpers.base_detector import detect_base

# Digital Forensics
from modules.digital_forensics.analyze import get_hashes, analyze_metadata, hex_tool
from modules.digital_forensics.steganography import encode_message, decode_message
from modules.digital_forensics.exif_extractor import extract_exif

# Tools
from modules.tools.metadata_analyzer import extract_metadata
from modules.tools.hex_tool import file_to_hex, hex_to_file

# Cryptography
from modules.cryptography.crypto_tool import custom_encrypt, custom_decrypt
from modules.cryptography.aes_tool import aes_encrypt, aes_decrypt

# -------------------- APP CONFIG --------------------
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 128 * 1024 * 1024  # 128 MB limit

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# -------------------- HOME --------------------
@app.route('/')
def index():
    return render_template('index.html')

# -------------------- CTF MODULE --------------------
@app.route('/ctf')
def ctf_main():
    return render_template('ctf_helpers.html')

@app.route('/ctf/base-detector', methods=['POST'])
def base_detector():
    encoded_text = request.form.get('encoded_text', '')
    base_result = detect_base(encoded_text)
    return render_template('ctf_helpers.html', base_result=base_result, encoded_input=encoded_text)

@app.route('/ctf/decode', methods=['POST'])
def decode_route():
    input_text = request.form.get('input_text', '')
    encoding = request.form.get('encoding', '')
    result = decode_text(input_text, encoding)
    return render_template('ctf_helpers.html', decode_result=result, input_text=input_text, selected_encoding=encoding)

# -------------------- DIGITAL FORENSICS --------------------
@app.route('/forensics')
def forensics_main():
    return render_template('forensics.html')

@app.route('/forensics/hash', methods=['POST'])
def compute_hashes():
    uploaded_file = request.files['file']
    if uploaded_file:
        filepath = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
        uploaded_file.save(filepath)
        hashes = get_hashes(filepath)
        return render_template('forensics.html', hash_result=hashes)
    return redirect('/forensics')

@app.route('/forensics/meta-analyze', methods=['POST'])
def metadata_analyzer():
    uploaded_file = request.files['file']
    if uploaded_file:
        filepath = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
        uploaded_file.save(filepath)
        metadata, file_type = extract_metadata(filepath)
        return render_template('forensics.html', meta_result=metadata, file_type=file_type)
    return redirect('/forensics')

# -------------------- STEGANOGRAPHY --------------------
@app.route('/tools/stego/encode', methods=['POST'])
def stego_encode():
    if 'image' not in request.files or 'message' not in request.form:
        return render_template('forensics.html', stego_result="❌ Invalid form data.")

    image = request.files['image']
    message = request.form['message']
    if not image or not message:
        return render_template('forensics.html', stego_result="❌ Image and message required.")

    input_path = os.path.join(UPLOAD_FOLDER, image.filename)
    output_path = os.path.join(UPLOAD_FOLDER, f"encoded_{image.filename}")
    image.save(input_path)

    encode_message(input_path, message, output_path)

    return render_template(
        'forensics.html',
        stego_result="✅ Message encoded successfully in image.",
        encoded_image=os.path.basename(output_path)
    )

@app.route('/tools/stego/decode', methods=['POST'])
def stego_decode():
    if 'image' not in request.files:
        return render_template('forensics.html', stego_result="❌ No image uploaded.")

    image = request.files['image']
    if image.filename == '':
        return render_template('forensics.html', stego_result="❌ No image selected.")

    input_path = os.path.join(UPLOAD_FOLDER, image.filename)
    image.save(input_path)

    # Get hidden message and clean it
    hidden_message = decode_message(input_path)
    cleaned_message = hidden_message.strip('\n\r\t ')

    return render_template('forensics.html', stego_result=cleaned_message)

# -------------------- TOOLS MODULE --------------------
@app.route('/tools')
def tools_main():
    return render_template('tools.html')

@app.route('/tools/metadata', methods=['POST'])
def metadata_tools():
    uploaded_file = request.files['file']
    if uploaded_file:
        filepath = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
        uploaded_file.save(filepath)
        metadata, file_type = extract_metadata(filepath)
        return render_template('tools.html', metadata=metadata, file_type=file_type)
    return redirect('/tools')

@app.route('/tools/exif', methods=['POST'])
def exif_extractor():
    uploaded_file = request.files['image']
    if uploaded_file:
        filepath = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
        uploaded_file.save(filepath)
        exif_data = extract_exif(filepath)
        return render_template('forensics.html', exif_data=exif_data)
    return redirect('/forensics')

@app.route('/tools/hex-viewer', methods=['POST'])
def hex_viewer_tools():
    uploaded_file = request.files['file']
    if uploaded_file:
        filepath = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
        uploaded_file.save(filepath)
        hex_data = file_to_hex(filepath)
        return render_template('tools.html', hex_data=hex_data)
    return redirect('/tools')

@app.route('/tools/hex-to-image', methods=['POST'])
def hex_to_file_route():
    hex_file = request.files.get('hex_file')
    filetype = request.form.get('filetype', 'png')

    if hex_file:
        try:
            hex_data = hex_file.read().decode('utf-8')
            output_filename = f"converted_output.{filetype}"
            output_path = hex_to_file(hex_data, os.path.join(UPLOAD_FOLDER, output_filename))
            return render_template('tools.html', hex_image=output_filename)
        except Exception as e:
            return render_template('tools.html', error={"hex": str(e)})
    return render_template('tools.html', error={"hex": "No HEX file uploaded."})

@app.route('/crypto')
def crypto_main():
    return render_template('cryptography.html', aes_data={}, active_tab='caesar')

@app.route('/crypto/encrypt', methods=['POST'])
def encrypt_text():
    plain_text = request.form.get('plain_text', '')
    key = request.form.get('key', '5')
    encrypted_text = custom_encrypt(plain_text, key)
    return render_template('cryptography.html', plain_text=plain_text, encrypted_text=encrypted_text, aes_data={}, active_tab='caesar')

@app.route('/crypto/decrypt', methods=['POST'])
def decrypt_text():
    cipher_text = request.form.get('cipher_text', '')
    key = request.form.get('key', '5')
    decrypted_text = custom_decrypt(cipher_text, key)
    return render_template('cryptography.html', cipher_text=cipher_text, decrypted_text=decrypted_text, aes_data={}, active_tab='caesar')

@app.route('/crypto/aes/encrypt', methods=['POST'])
def aes_encrypt_route():
    text = request.form.get('plain_text', '')
    key = request.form.get('key', '')
    try:
        result = aes_encrypt(text, key)
        return render_template(
            'cryptography.html',
            aes_plain_text=text,
            aes_encrypted=result,
            aes_data={},  # Ensure aes_data is always passed
            active_tab='aes'
        )
    except Exception as e:
        return render_template(
            'cryptography.html',
            aes_plain_text=text,
            aes_encrypted={"error": str(e)},
            aes_data={},
            active_tab='aes'
        )

@app.route('/crypto/aes/decrypt', methods=['POST'])
def aes_decrypt_route():
    ciphertext = request.form.get('ciphertext')
    nonce = request.form.get('nonce')
    tag = request.form.get('tag')
    key = request.form.get('key')
    aes_data = {"ciphertext": ciphertext, "nonce": nonce, "tag": tag}
    try:
        decrypted = aes_decrypt(ciphertext, nonce, tag, key)
        return render_template(
            'cryptography.html',
            aes_data=aes_data,
            aes_decrypted=decrypted,
            active_tab='aes'
        )
    except Exception as e:
        return render_template(
            'cryptography.html',
            aes_data=aes_data,
            aes_decrypted=f"❌ Error: {e}",
            active_tab='aes'
        )


# -------------------- FILES --------------------
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# -------------------- ERROR HANDLING --------------------
@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(e):
    return render_template('forensics.html', error={"hex": "⚠️ Uploaded data too large! Limit is 128MB."}), 413

# -------------------- RUN --------------------
if __name__ == "__main__":
    app.run(debug=True)

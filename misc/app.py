import base64
import hashlib
import math
import os
import time
import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, request, redirect, url_for, session, flash, Response, render_template
from flask_mysqldb import MySQL
import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL configurations
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'asdf'
app.config['MYSQL_DB'] = 'cryptdb'
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024 * 10  # 1GB

mysql = MySQL(app)

# Paths to the key files
public_key_path = 'keys/pubKey/public_key.pem'
private_key_path = 'keys/privKey/private_key.pem'

# Folder paths
folders = ['uploads', 'content']
for folder in folders:
    os.makedirs(folder, exist_ok=True)


# Load the public key from a PEM file
def load_public_key(public_key_path):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key


# Load the private key from a PEM file
def load_private_key(private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


# Load the keys
public_key = load_public_key(public_key_path)
private_key = load_private_key(private_key_path)


# Helper functions for encryption and decryption
def divide_chunks(file_path, chunk_size=1024 * 1024):
    chunks = []
    start_time = time.time()
    with open(file_path, 'rb') as file:
        while chunk := file.read(chunk_size):
            chunks.append(chunk)
    chunk_time = time.time() - start_time
    return chunks, chunk_time


def generate_aes_key(vid, mac_address, previous_key=None):
    x = int.from_bytes(hashlib.sha256((vid + mac_address).encode()).digest(), 'big')
    mac_int = int.from_bytes(mac_address.encode(), 'big')
    if previous_key:
        y = int.from_bytes(hashlib.sha256((previous_key + mac_address).encode()).digest(), 'big')
        key = (x ** 3 + y * x + mac_int) % (2 ** 256)
    else:
        key = (x ** 3 + mac_int) % (2 ** 256)
    return key.to_bytes(32, 'big')


def save_encrypted_chunks(encrypted_chunks, output_dir, video_name):
    os.makedirs(output_dir, exist_ok=True)
    for i, chunk in enumerate(encrypted_chunks):
        with open(os.path.join(output_dir, f'{video_name}_encrypted_chunk_{i}.enc'), 'wb') as file:
            file.write(chunk)


def load_encrypted_chunks(output_dir, video_name):
    encrypted_chunks = []
    files = [f for f in os.listdir(output_dir) if f.startswith(f'{video_name[:-4]}_encrypted_chunk_')]
    files = sorted(files, key=lambda x: int(x.split('_')[-1].split('.')[0]))
    for file in files:
        with open(os.path.join(output_dir, file), 'rb') as f:
            encrypted_chunks.append(f.read())
    return encrypted_chunks


def encrypt_video(file_path, rsa_public_key, mac_address, output_dir, video_name):
    file_size = os.path.getsize(file_path) / (1024 * 1024)  # File size in MB
    start_time = time.time()

    # Get chunks and chunk_time
    chunks, chunk_time = divide_chunks(file_path)

    # Generate vid from the first chunk's first 16 bytes
    vid = base64.b64encode(chunks[0][:16]).decode()

    # Generate AES key
    aes_key = generate_aes_key(vid, mac_address)

    # Encrypt the AES key with RSA public key
    encrypted_aes_key = rsa_public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Encrypt chunks with AES key
    encrypted_chunks = []
    for chunk in chunks:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_chunk = encryptor.update(chunk) + encryptor.finalize()
        encrypted_chunks.append(iv + encrypted_chunk)

    # Save encrypted AES key
    with open(os.path.join(output_dir, 'encrypted_key.bin'), 'wb') as file:
        file.write(encrypted_aes_key)

    # Save encrypted chunks
    save_encrypted_chunks(encrypted_chunks, output_dir, video_name)

    encryption_time = time.time() - start_time
    return vid, file_size, chunk_time, encryption_time


def decrypt_video(output_dir, rsa_private_key, mac_address, video_name, output_path, video_id):
    start_time = time.time()
    encrypted_chunks = load_encrypted_chunks(output_dir, video_name)
    with open(os.path.join(output_dir, 'encrypted_key.bin'), 'rb') as file:
        encrypted_aes_key = file.read()
    aes_key = rsa_private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    decrypted_chunks = []
    for chunk in encrypted_chunks:
        iv = chunk[:16]
        encrypted_chunk = chunk[16:]
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_chunk = decryptor.update(encrypted_chunk) + decryptor.finalize()
        decrypted_chunks.append(decrypted_chunk)
    decryption_time = time.time() - start_time

    start_time = time.time()

    with open(os.path.join(output_path, video_name), 'wb') as file:
        for chunk in decrypted_chunks:
            file.write(chunk)
    combine_time = time.time() - start_time

    # Update decryption and combining chunks times in metrics
    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE metrics
        SET decryption_time = %s, combine_time = %s
        WHERE file_name = %s and video_id =%s
    """, (decryption_time, combine_time, video_name[:-4], video_id))
    mysql.connection.commit()
    cur.close()


@app.route('/')
def index():
    if 'username' not in session:
        flash('You need to login first', 'warning')
        return redirect(url_for('login'))
    username = session['username']
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT Videos.video_id, Videos.title, Videos.description, Videos.file_name
        FROM Videos
        JOIN Users ON Videos.recipient_id = Users.user_id
        WHERE Users.username = %s
    """, (username,))
    videos = cur.fetchall()
    cur.close()
    return render_template('index.html', videos=videos)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO Users (username, email, password_hash) VALUES (%s, %s, %s)",
                    (username, email, hashed_password))
        mysql.connection.commit()
        cur.close()
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM Users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        if user and bcrypt.checkpw(password, user[3].encode('utf-8')):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        flash('You need to login first', 'warning')
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        recipient_username = request.form['recipient']
        mac_address = request.form['mac_address']
        file = request.files['video_file']
        if file:
            filename = file.filename
            recipient_file_path = os.path.join('uploads',recipient_username)
            if not os.path.exists(recipient_file_path):
                os.makedirs(recipient_file_path, exist_ok=True)
            file_path=os.path.join(recipient_file_path,filename)
            file.save(file_path)
            cur = mysql.connection.cursor()
            cur.execute("SELECT user_id FROM Users WHERE username = %s", (recipient_username,))
            recipient = cur.fetchone()

            if recipient:
                recipient_id = recipient[0]
                video_name = filename.split('.')[0]
                recipient_folder = os.path.join('content', recipient_username)
                encrypted_folder = os.path.join(recipient_folder, 'encrypted')
                decrypted_folder = os.path.join(recipient_folder, 'decrypted')
                if not os.path.exists(recipient_folder):
                    os.makedirs(recipient_folder, exist_ok=True)
                if not os.path.exists(decrypted_folder):
                    os.makedirs(decrypted_folder, exist_ok=True)
                if not os.path.exists(encrypted_folder):
                    os.makedirs(encrypted_folder)
                encrypted_folder = os.path.join(recipient_folder, 'encrypted', video_name)
                if not os.path.exists(encrypted_folder):
                    os.makedirs(encrypted_folder)
                output_dir = f'content/{recipient_username}/encrypted/{video_name}'
                if not os.path.exists(output_dir):
                    os.makedirs(output_dir, exist_ok=True)
                vid, file_size, chunk_time, encryption_time = encrypt_video(file_path, public_key, mac_address,
                                                                            encrypted_folder, video_name)
                uploader_username = session['username']
                cur.execute("SELECT user_id FROM Users WHERE username = %s", (uploader_username,))
                uploader = cur.fetchone()
                #cur = mysql.connection.cursor()
                cur.execute("""
                                    INSERT INTO Videos (title, description, file_name,file_path, uploader_id, recipient_id, mac_address, vid)
                                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                                """,
                            (title, description, filename, file_path, uploader[0], recipient_id, mac_address, vid))
                cur.execute("""
                       SELECT Videos.video_id
                       FROM Videos
                       JOIN Users ON Videos.recipient_id = Users.user_id
                       WHERE Videos.title= %s and Videos.description= %s and Videos.file_name=%s and Videos.uploader_id= %s and videos.recipient_id=%s and videos.mac_address=%s and videos.vid=%s
                   """, (title, description, filename, uploader[0], recipient_id, mac_address, vid))
                video_id = cur.fetchone()
                # Record metrics
                file_size_mb = "{:.2f}".format(os.path.getsize(file_path) / (1024 * 1024))
                cur.execute("""
                                    INSERT INTO metrics (Video_id,file_size, chunk_time, encryption_time, decryption_time,combine_time, file_name,recipient_id)
                                    VALUES (%s,%s, %s, %s, %s, %s,%s,%s)
                                """, (
                    video_id, file_size_mb, chunk_time, encryption_time, 0, 0,
                    video_name, recipient_id))  # Decryption time is initially 0

                mysql.connection.commit()
                cur.close()
                #os.remove(file_path)
                flash('Video uploaded and encrypted successfully!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Recipient not found', 'danger')
        else:
            flash('No file uploaded', 'warning')
    return render_template('upload.html')


@app.route('/watch/<int:video_id>')
def watch(video_id):
    if 'username' not in session:
        flash('You need to login first', 'warning')
        return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT video_id, file_name, recipient_id, mac_address FROM Videos WHERE video_id = %s", (video_id,))
    video = cur.fetchone()
    cur.close()
    if not video:
        flash('Video not found', 'danger')
        return redirect(url_for('index'))

    video_id, file_name, recipient_id, mac_address = video
    cur = mysql.connection.cursor()
    cur.execute("SELECT username FROM Users WHERE user_id = %s", (recipient_id,))
    recipient = cur.fetchone()
    cur.close()

    if not recipient or session['username'] != recipient[0]:
        flash('You are not authorized to view this video', 'danger')
        return redirect(url_for('index'))

    # Proceed to decryption if the user is authorized
    recipient_username = recipient[0]
    encrypted_folder = os.path.join('content', recipient_username, 'encrypted', file_name[:-4])
    if not os.path.exists(os.path.join('content', recipient_username, 'decrypted', file_name[:-4])):
        os.makedirs(os.path.join('content', recipient_username, 'decrypted', file_name[:-4]))
    decrypted_file_path = os.path.join('content', recipient_username, 'decrypted', file_name[:-4])
    decrypted_file = os.path.join('content', recipient_username, 'decrypted', file_name[:-4], file_name)
    decrypt_video(encrypted_folder, private_key, mac_address, file_name, decrypted_file_path, video_id)

    # return Response(
    #     open(decrypted_file_path, 'rb').read(),
    #     mimetype='video/mp4',
    #     headers={"Content-Disposition": f"attachment;filename={file_name}"}
    # )

    def generate():
        with open(decrypted_file, 'rb') as f:
            while chunk := f.read(1024 * 1024):
                yield chunk
        #os.remove(decrypted_file_path)

    return Response(generate(), content_type='video/mp4')

@app.route('/metrics')
def metrics():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT file_size, chunk_time, encryption_time, decryption_time, combine_time, file_name
        FROM metrics join users on users.user_id=metrics.recipient_id
        WHERE users.username = %s ORDER BY metrics.Video_id DESC
        LIMIT 5
    """,(session['username'],))
    rows = cur.fetchall()
    cur.close()

    if not rows:
        return render_template('metrics.html', plot_url=None, message="No metrics data available.")

    # Sort by file size
    rows = sorted(rows, key=lambda x: x[0])

    # Limit to top 5 entries
    if len(rows) > 5:
        rows = rows[-5:]
    print(rows)

    file_sizes = [row[0] for row in rows]
    chunk_times = [row[1] for row in rows]
    encryption_times = [row[2] for row in rows]
    decryption_times = [row[3] for row in rows]
    combine_times = [row[4] for row in rows]
    file_names = [row[5] for row in rows]

    # Determine x-axis scale
    max_file_size = max(file_sizes)
    x_limit = math.ceil(max_file_size)

    plt.figure(figsize=(12, 8))
    plt.suptitle('Video Processing Metrics')

    # Chunking Time Plot
    plt.subplot(2, 2, 1)
    plt.plot(file_sizes, chunk_times, 'o-')
    plt.title('Chunking Time vs File Size')
    plt.xlabel('File Size (MB)')
    plt.ylabel('Chunking Time (seconds)')
    for i, file_name in enumerate(file_names):
        plt.annotate(file_name, (file_sizes[i], chunk_times[i]))
    plt.xlim(0, x_limit)

    # Encryption Time Plot
    plt.subplot(2, 2, 2)
    plt.plot(file_sizes, encryption_times, 'o-')
    plt.title('Encryption Time vs File Size')
    plt.xlabel('File Size (MB)')
    plt.ylabel('Encryption Time (seconds)')
    for i, file_name in enumerate(file_names):
        plt.annotate(file_name, (file_sizes[i], encryption_times[i]))
    plt.xlim(0, x_limit)

    # Decryption Time Plot
    plt.subplot(2, 2, 3)
    plt.plot(file_sizes, decryption_times, 'o-')
    plt.title('Decryption Time vs File Size')
    plt.xlabel('File Size (MB)')
    plt.ylabel('Decryption Time (seconds)')
    for i, file_name in enumerate(file_names):
        plt.annotate(file_name, (file_sizes[i], decryption_times[i]))
    plt.xlim(0, x_limit)

    # Combining Chunks Time Plot
    plt.subplot(2, 2, 4)
    plt.plot(file_sizes, combine_times, 'o-')
    plt.title('Combining Chunks Time vs File Size')
    plt.xlabel('File Size (MB)')
    plt.ylabel('Combining Chunks Time (seconds)')
    for i, file_name in enumerate(file_names):
        plt.annotate(file_name, (file_sizes[i], combine_times[i]))
    plt.xlim(0, x_limit)

    plt.tight_layout(rect=(0, 0, 1, 0.96))  # Corrected tight_layout parameters
    plt.savefig('static/metrics_plot.png')
    plt.close()

    return render_template('metrics.html', plot_url='static/metrics_plot.png')


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)

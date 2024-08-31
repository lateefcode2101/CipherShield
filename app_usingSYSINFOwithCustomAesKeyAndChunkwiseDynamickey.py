import base64
import logging
import math
import os
import time
import hashlib
import bcrypt
from flask import jsonify
from collections import Counter
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, request, redirect, url_for, session, flash, Response, render_template
from flask_mysqldb import MySQL
from matplotlib import pyplot as plt

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL configurations
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'asdf'
app.config['MYSQL_DB'] = 'cryptdb'
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024 * 100  # 10GB
app.config['SESSION_PERMANENT'] = True

# app.permanent_session_lifetime = timedelta(minutes=5)  # Set timeout to 30 minutes
#
# @app.before_request
# def before_request():
#     session.permanent = True
#     session.modified = True


mysql = MySQL(app)

# Paths to the key files
global_i = None
previous_aes_key = None
b = None
SAVE_DYNAMIC_KEYS = True
# Define the paths to public and private keys
public_key_path = 'keys/pubKey/public_key.pem'
private_key_path = 'keys/privKey/private_key.pem'
a = 0
i = 0
logging.basicConfig(level=logging.DEBUG)
debug_flag = False
# Folder paths
folders = ['uploads', 'content']
for folder in folders:
    os.makedirs(folder, exist_ok=True)


# Load the public key from a PEM file
def load_public_key(public_key_folder_path):
    with open(public_key_folder_path, 'rb') as key_file:
        public_key_ = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key_


# Load the private key from a PEM file
def load_private_key(private_key_folder_path):
    with open(private_key_folder_path, 'rb') as key_file:
        private_key_ = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key_


# Load the keys
public_key = load_public_key(public_key_path)
private_key = load_private_key(private_key_path)


# Helper functions for encryption and decryption
def divide_chunks(file_path, chunk_size=1024 * 1024):
    chunks = []
    start_time = time.time()

    with open(file_path, 'rb') as file:
        while chunk := file.read(chunk_size):
            # print("writing chunks")
            chunks.append(chunk)
    chunking_time = time.time() - start_time
    return chunks, chunking_time


def save_encrypted_chunks(encrypted_chunks, output_dir, video_name, encryption_time, video_id):
    os.makedirs(output_dir, exist_ok=True)
    user = session['username']
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id FROM Users WHERE username = %s", (user,))
    user_id = cur.fetchone()
    for _i_, chunk in enumerate(encrypted_chunks):
        entropy = calculate_entropy(chunk)
        cur.execute("""
                        INSERT INTO chunk_metrics (video_name, chunk_index, chunk_size_mb, processing_time, entropy, user_id,video_id)
                        VALUES (%s, %s, %s, %s, %s, %s,%s)
                    """, (video_name, _i_, len(chunk) / (1024 * 1024), encryption_time, entropy, user_id, video_id))

        with open(os.path.join(output_dir, f'{video_name}_encrypted_chunk_{_i_}.enc'), 'wb') as file:
            file.write(chunk)
    mysql.connection.commit()
    cur.close()


def load_encrypted_chunks(output_dir, video_name):
    encrypted_chunks = []
    files = [f for f in os.listdir(output_dir) if f.startswith(f'{video_name[:-4]}_encrypted_chunk_')]
    files = sorted(files, key=lambda x: int(x.split('_')[-1].split('.')[0]))
    for file in files:
        with open(os.path.join(output_dir, file), 'rb') as f:
            encrypted_chunks.append(f.read())
    return encrypted_chunks


import os


def generate_aes_key_with_ecc_equation(vid_or_key, systemUniqueInformation, previous_aes_key=None, first_chunk=True):
    systemUniqueInformation = int.from_bytes(str(systemUniqueInformation).encode(), 'big')

    if first_chunk:
        a = int.from_bytes(vid_or_key.encode(), 'big')
        vid_or_key_bytes = vid_or_key.encode()  # Convert to bytes
    else:
        a = int.from_bytes(vid_or_key, byteorder='big')
        vid_or_key_bytes = vid_or_key  # Already in bytes

    # Generate a deterministic x-coordinate using a hash function
    x_hash = hashlib.sha256(vid_or_key_bytes).digest()
    x = int.from_bytes(x_hash, byteorder='big')

    # Include previous AES key in the hash to ensure the new key is dependent on it
    if previous_aes_key:
        combined_input = vid_or_key_bytes + previous_aes_key
    else:
        combined_input = vid_or_key_bytes

    # Generate another hash including the previous AES key (if available)
    additional_entropy = hashlib.sha256(combined_input).digest()

    # Combine the additional entropy into the systemUniqueInformation
    systemUniqueInformation = systemUniqueInformation ^ int.from_bytes(additional_entropy[:16], byteorder='big')

    # Compute Key using the ECC equation
    key_int = int(math.sqrt((x ** 3 + a * x + systemUniqueInformation) % (2 ** 256)))
    key_bytes = key_int.to_bytes(32, 'big')

    return key_bytes


def generate_custom_timestamp():
    # Get the current date and time
    current_time = datetime.now()

    # Format the current date and time in the desired format:
    # ddmmyyyyhh24miss: Day, Month, Year, Hour (24-hour format), Minutes, Seconds
    # Milliseconds: using `%f` which includes microseconds; we'll convert it to milliseconds by slicing
    timestamp = current_time.strftime("%d%m%Y%H%M%S") + str(current_time.microsecond)[:3]

    return timestamp


def generate_system_specific_data(uuid_from_form):
    # Convert UUID to bytes and hash it to create a unique system-specific value
    machine_id = str(uuid_from_form).replace("-", "").encode()  # Machine ID (UUID from form)

    if debug_flag:
        print('machine id is ', machine_id)
        print('===length of machine id is ', len(machine_id))

    # Hash the machine ID
    hashed_data = hashlib.sha256(machine_id).digest()
    if debug_flag:
        print('Hashed data is: ', hashed_data)

    # Convert the hash to an integer for use as the x-coordinate
    unique_sys_info = int.from_bytes(hashed_data, byteorder='big')
    if debug_flag:
        print('Unique system-specific information (b coefficient) is: ', unique_sys_info)

    return unique_sys_info


def encrypt_video(file_path, rsa_public_key, systemUniqueInformation, output_dir, video_name):
    global previous_aes_key, debug_flag
    file_size = os.path.getsize(file_path) / (1024 * 1024)  # File size in MB
    start_time = time.perf_counter()
    dynamic_keys = []
    chunk_delays = []
    key_gen_delays = []

    # Get chunks and chunking_time
    chunks, chunking_time = divide_chunks(file_path)

    # print(f'hardware guid is {systemUniqueInformation}')

    # Generate vid from the first chunk's first 16 bytes
    vid = base64.b64encode(chunks[0][:16]).decode()
    # print('vid with .decode', vid)

    # Compute the key for the first chunk
    key_gen_start_time = time.perf_counter()

    aes_key = generate_aes_key_with_ecc_equation(vid, systemUniqueInformation, first_chunk=True)

    key_gen_end_time = time.perf_counter()
    key_gen_delay = key_gen_end_time - key_gen_start_time
    key_gen_delays.append((0, key_gen_delay))
    dynamic_keys.append(aes_key)
    print(f'aes key from system information during encryption: {aes_key} with size {len(aes_key)} ')
    print(f'size of master aes key during encryption is {len(aes_key)}')

    # Encrypt the AES key with RSA public key
    encrypted_aes_key = rsa_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print('size of encrypted aes key is', len(encrypted_aes_key))
    if SAVE_DYNAMIC_KEYS:
        print('video name while saving dynamic keys is ', video_name)
        keys_filename = os.path.join(output_dir, f"{video_name}_All_Dynamic_Keys.txt")
        save_dynamic_keys(dynamic_keys, keys_filename)

    # Encrypt chunks with AES key
    encrypted_chunks = []
    for idx, chunk in enumerate(chunks):
        chunk_encryption_start_time = time.perf_counter()

        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend()).encryptor()
        encrypted_chunk = encryptor.update(chunk) + encryptor.finalize()
        if idx == 0:
            encrypted_chunks.append(encrypted_aes_key + iv + encrypted_chunk)
        else:
            encrypted_chunks.append(iv + encrypted_chunk)

        # Generate the key for the next chunk using the current AES key
        key_gen_start_time = time.perf_counter()
        previous_aes_key = aes_key  # Store current key before generating the next one
        aes_key = generate_aes_key_with_ecc_equation(aes_key, systemUniqueInformation, previous_aes_key,
                                                     first_chunk=False)
        key_gen_end_time = time.perf_counter()
        key_gen_delay = key_gen_end_time - key_gen_start_time
        key_gen_delays.append((idx, key_gen_delay))  # (chunk_index, delay)

        chunk_end_time = time.perf_counter()
        chunk_encryption_delay = chunk_end_time - chunk_encryption_start_time

        chunk_delays.append(chunk_encryption_delay)
        dynamic_keys.append(aes_key)

    encryption_time = time.perf_counter() - start_time

    if SAVE_DYNAMIC_KEYS:
        keys_filename = os.path.join(output_dir, f"{video_name[:-4]}_All_Dynamic_Keys.txt")
        save_dynamic_keys(dynamic_keys, keys_filename)
    # Save encrypted AES key
    with open(os.path.join(output_dir, 'encrypted_key.bin'), 'wb') as file:
        file.write(encrypted_aes_key)

    return vid, file_size, chunking_time, encryption_time, key_gen_delays, chunk_delays, encrypted_chunks


def calculate_entropy(data):
    """Calculate the entropy of a given byte sequence."""
    if len(data) == 0:
        return 0
    counter = Counter(data)
    probabilities = [count / len(data) for count in counter.values()]
    entropy = -sum(p * math.log2(p) for p in probabilities)
    return entropy


def decrypt_video(output_dir, rsa_private_key, systemUniqueInformation, video_name, output_path, video_id):
    start_time = time.time()
    dynamic_keys = []
    encrypted_chunks = load_encrypted_chunks(output_dir, video_name)
    total_chunks = len(encrypted_chunks)

    # Retrieve the encrypted AES key from the first chunk
    first_chunk = encrypted_chunks[0]
    encrypted_aes_key = first_chunk[:256]  # Assuming RSA key size is 2048 bits (256 bytes)
    iv = first_chunk[256:272]  # Initialization vector (assuming 16 bytes for AES)
    encrypted_chunk = first_chunk[272:]

    # Decrypt the AES key using the RSA private key
    aes_key = rsa_private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print(f'master aes key after decryption: {aes_key}')
    dynamic_keys.append(aes_key)

    # Decrypt the first chunk
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_chunk = decryptor.update(encrypted_chunk) + decryptor.finalize()
    decrypted_chunks = [decrypted_chunk]
    aes_key = generate_aes_key_with_ecc_equation(aes_key, systemUniqueInformation, first_chunk=False)
    dynamic_keys.append(aes_key)

    # Decrypt the remaining chunks
    for idx, chunk in enumerate(encrypted_chunks[1:]):
        print('idx while decrypting is ', idx)
        iv = chunk[:16]  # Initialization vector
        encrypted_chunk = chunk[16:]

        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_chunk = decryptor.update(encrypted_chunk) + decryptor.finalize()
        decrypted_chunks.append(decrypted_chunk)

        # Generate the key for the next chunk using the current AES key
        aes_key = generate_aes_key_with_ecc_equation(aes_key, systemUniqueInformation, first_chunk=False)
        dynamic_keys.append(aes_key)

        # # Update progress
        # progress = (idx + 2) / total_chunks * 100
        # yield jsonify({'progress': progress})

    decryption_time = time.time() - start_time
    start_time = time.time()

    if SAVE_DYNAMIC_KEYS:
        keys_filename = os.path.join(output_path, f"{video_name[:-4]}_All_Dynamic_Keys.txt")
        save_dynamic_keys(dynamic_keys, keys_filename)

    # Write the decrypted chunks to the output file
    with open(os.path.join(output_path, video_name), 'wb') as file:
        for chunk in decrypted_chunks:
            file.write(chunk)
            print('combining chunks to decrypted file')

    combine_time = time.time() - start_time

    # Update decryption and combining chunks times in metrics
    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE metrics
        SET decryption_time = %s, combine_time = %s
        WHERE file_name = %s and video_id = %s
    """, (decryption_time, combine_time, video_name[:-4], video_id))
    mysql.connection.commit()
    cur.close()


def save_dynamic_keys(keys, filename):
    with open(filename, 'w') as f:
        for i, key in enumerate(keys):
            f.write(f"{os.path.basename(filename)} Key {i}: {key}\n")


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
        uuid_from_form = request.form['uuid']
        file = request.files['video_file']
        if file:
            filename = file.filename
            recipient_file_path = os.path.join('uploads', recipient_username)
            if not os.path.exists(recipient_file_path):
                os.makedirs(recipient_file_path, exist_ok=True)
            file_path = os.path.join(recipient_file_path, filename)
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
                metrics_folder = os.path.join(recipient_folder, 'metrics')
                if not os.path.exists(recipient_folder):
                    os.makedirs(recipient_folder, exist_ok=True)
                if not os.path.exists(decrypted_folder):
                    os.makedirs(decrypted_folder, exist_ok=True)
                if not os.path.exists(encrypted_folder):
                    os.makedirs(encrypted_folder)
                if not os.path.exists(metrics_folder):
                    os.makedirs(metrics_folder, exist_ok=True)
                encrypted_folder = os.path.join(recipient_folder, 'encrypted', video_name)
                if not os.path.exists(encrypted_folder):
                    os.makedirs(encrypted_folder)
                output_dir = f'content/{recipient_username}/encrypted/{video_name}'
                if not os.path.exists(output_dir):
                    os.makedirs(output_dir, exist_ok=True)
                systemUniqueInformation = generate_system_specific_data(uuid_from_form)
                print('size of systemUniqueInformation ', len(str(systemUniqueInformation)))
                vid, file_size, chunk_time, encryption_time, key_gen_delays, chunk_delays, encrypted_chunks = encrypt_video(
                    file_path, public_key,
                    systemUniqueInformation,
                    encrypted_folder, video_name)
                uploader_username = session['username']
                cur.execute("SELECT user_id FROM Users WHERE username = %s", (uploader_username,))
                uploader = cur.fetchone()
                cur.execute("""
                                    INSERT INTO Videos (title, description, file_name,file_path, uploader_id, recipient_id, UUID, vid)
                                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                                """,
                            (
                                title, description, filename, file_path, uploader[0], recipient_id,
                                systemUniqueInformation,
                                vid))
                cur.execute("""
                       SELECT Videos.video_id
                       FROM Videos
                       JOIN Users ON Videos.recipient_id = Users.user_id
                       WHERE Videos.title= %s and Videos.description= %s and Videos.file_name=%s and Videos.uploader_id= %s and videos.recipient_id=%s and videos.UUID=%s and videos.vid=%s
                   """, (title, description, filename, uploader[0], recipient_id, systemUniqueInformation, vid))
                video_id = cur.fetchone()
                # Record metrics
                file_size_mb = "{:.2f}".format(os.path.getsize(file_path) / (1024 * 1024))
                cur.execute("""
                                    INSERT INTO metrics (Video_id,file_size, chunk_time, encryption_time, decryption_time,combine_time, file_name,recipient_id)
                                    VALUES (%s,%s, %s, %s, %s, %s,%s,%s)
                                """, (
                    video_id, file_size_mb, chunk_time, encryption_time, 0, 0,
                    video_name, recipient_id))  # Decryption time is initially 0

                # Save chunk delays to the database
                cur = mysql.connection.cursor()
                cur.execute("SELECT user_id FROM Users WHERE username = %s", (session['username'],))
                recipient_id = cur.fetchone()
                for chunk_index, delay in key_gen_delays:
                    cur.execute("""
                                INSERT INTO key_gen_delays ( video_name, chunk_index, delay, recipient_id,video_id)
                                VALUES (%s, %s, %s, %s, %s)
                            """, (video_name, chunk_index, delay, recipient_id, video_id))
                for idx, delay in enumerate(chunk_delays):
                    cur.execute("""
                                INSERT INTO chunk_delays (video_id, video_name, chunk_index, delay, recipient_id)
                                VALUES (%s, %s, %s, %s, %s)
                            """, (video_id, video_name, idx, delay, recipient_id))
                save_encrypted_chunks(encrypted_chunks, output_dir, video_name, encryption_time, video_id)
                mysql.connection.commit()
                cur.close()

                flash('Video uploaded and encrypted successfully!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Recipient not found', 'danger')
    else:
        cur = mysql.connection.cursor()
        cur.execute("SELECT username FROM users")
        users = cur.fetchall()
        cur.close()
        flash('No file uploaded', 'warning')
    return render_template('upload.html', users=users)


@app.route('/watch/<int:video_id>')
def watch(video_id):
    if 'username' not in session:
        flash('You need to login first', 'warning')
        return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT video_id, file_name, recipient_id, UUID FROM Videos WHERE video_id = %s", (video_id,))
    video = cur.fetchone()
    cur.close()
    if not video:
        flash('Video not found', 'danger')
        return redirect(url_for('index'))

    video_id, file_name, recipient_id, hardware_uuid = video
    print('hardware uuid is ', hardware_uuid)
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
    decrypt_video(encrypted_folder, private_key, hardware_uuid, file_name, decrypted_file_path, video_id)

    def generate():
        with open(decrypted_file, 'rb') as f:
            while chunk := f.read(1024 * 1024):
                yield chunk

    return Response(generate(), content_type='video/mp4')


import matplotlib

matplotlib.use('Agg')


@app.route('/metrics')
def metrics():
    # Create user-specific metrics folder
    username = session['username']
    user_metrics_folder = os.path.join(os.path.abspath('content'), username, 'metrics')
    if not os.path.exists(user_metrics_folder):
        os.makedirs(user_metrics_folder, exist_ok=True)

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT file_size, chunk_time, encryption_time, decryption_time, combine_time, file_name
        FROM metrics join users on users.user_id=metrics.recipient_id
        WHERE users.username = %s ORDER BY metrics.Video_id DESC
        LIMIT 10
    """, (session['username'],))
    rows = cur.fetchall()
    cur.close()

    if not rows:
        return render_template('metrics.html', plot_url=None, message="No metrics data available.")

    # Sort by file size
    rows = sorted(rows, key=lambda x: x[0])

    # Limit to top 5 entries
    if len(rows) > 10:
        rows = rows[-10:]
    print(rows)

    file_sizes = [row[0] for row in rows]
    chunk_times = [row[1] for row in rows]
    encryption_times = [row[2] for row in rows]
    decryption_times = [row[3] for row in rows]
    combine_times = [row[4] for row in rows]
    file_names = [row[5] for row in rows]
    # video_id = [row[6] for row in rows]

    # Determine x-axis scale
    max_file_size = max(file_sizes)
    x_limit = math.ceil(max_file_size)

    plt.figure(figsize=(14, 14))
    plt.suptitle(f'Video Processing Metrics of {session['username']}')

    # Chunking Time Plot
    plt.subplot(4, 2, 1)
    plt.plot(file_sizes, chunk_times, 'o-')
    plt.title('Chunking Time vs File Size')
    plt.xlabel('File Size (MB)')
    plt.ylabel('Chunking Time (seconds)')
    # for _i_, file_name in enumerate(file_names):
    #     plt.annotate(file_name, (file_sizes[_i_], chunk_times[_i_]))
    plt.xlim(0, x_limit)
    plt.xticks(range(0, x_limit + 1, 50))  # Set ticks every 50 units

    # Encryption Time Plot
    plt.subplot(4, 2, 2)
    plt.plot(file_sizes, encryption_times, 'o-')
    plt.title('Encryption Time vs File Size')
    plt.xlabel('File Size (MB)')
    plt.ylabel('Encryption Time (seconds)')
    # for _i_, file_name in enumerate(file_names):
    #     plt.annotate(file_name, (file_sizes[_i_], encryption_times[_i_]))
    plt.xlim(0, x_limit)
    plt.xticks(range(0, x_limit + 1, 50))  # Set ticks every 50 units

    # Decryption Time Plot
    plt.subplot(4, 2, 3)
    plt.plot(file_sizes, decryption_times, 'o-')
    plt.title('Decryption Time vs File Size')
    plt.xlabel('File Size (MB)')
    plt.ylabel('Decryption Time (seconds)')
    # for _i_, file_name in enumerate(file_names):
    #     plt.annotate(file_name, (file_sizes[_i_], decryption_times[_i_]))
    plt.xlim(0, x_limit)
    plt.xticks(range(0, x_limit + 1, 50))  # Set ticks every 50 units

    # Combining Chunks Time Plot
    plt.subplot(4, 2, 4)
    plt.plot(file_sizes, combine_times, 'o-')
    plt.title('Combining Chunks Time vs File Size')
    plt.xlabel('File Size (MB)')
    plt.ylabel('Combining Chunks Time (seconds)')
    # for _i_, file_name in enumerate(file_names):
    #     plt.annotate(file_name, (file_sizes[_i_], combine_times[_i_]))
    plt.xlim(0, x_limit)
    plt.xticks(range(0, x_limit + 1, 50))  # Set ticks every 50 units

    # Encryption Delay Between Each Chunk (only if chunks > 500)
    for file_name in file_names:
        cur = mysql.connection.cursor()
        cur.execute("SELECT user_id FROM Users WHERE username = %s", (session['username'],))
        user_id = cur.fetchone()
        cur.execute("""
                SELECT chunk_index, delay
                FROM chunk_delays
                WHERE video_name = %s and recipient_id=%s 
                ORDER BY chunk_index ASC
            """, (file_name, user_id))
        chunk_delays = cur.fetchall()
        cur.close()

        if len(chunk_delays) > 500:
            chunk_indices = [cd[0] for cd in chunk_delays]
            delays = [cd[1] for cd in chunk_delays]
            print('chunk delays are ', len(chunk_delays))

            plt.subplot(4, 2, 5)
            plt.plot(chunk_indices, delays, '-')
            plt.title('Encryption Delay vs Number of Chunks')
            plt.xlabel('Number of Chunks')
            plt.ylabel('Encryption Delay (seconds)')
            plt.xticks(range(0, x_limit + 1, 50))  # Set ticks every 50 units

            break  # Only plot for the first file with more than 500 chunks
        # Key Generation Delay (only if chunks > 500)
    for file_name in file_names:
        cur = mysql.connection.cursor()
        cur.execute("SELECT user_id FROM Users WHERE username = %s", (session['username'],))
        user_id = cur.fetchone()
        cur.execute("""
                SELECT chunk_index, delay
                FROM key_gen_delays
                WHERE video_name = %s  and recipient_id=%s
                ORDER BY chunk_index ASC
        """, (file_name, user_id))
        key_gen_delays = cur.fetchall()
        cur.close()

        if len(key_gen_delays) > 500:
            chunk_indices = [kgd[0] for kgd in key_gen_delays]
            delays = [kgd[1] for kgd in key_gen_delays]

            plt.subplot(4, 2, 6)
            plt.plot(chunk_indices, delays, '-')
            plt.title('Key Generation Delay vs Number of Chunks')
            plt.xlabel('Number of Chunks')
            plt.ylabel('Key Generation Delay (seconds)')
            plt.xticks(range(0, x_limit + 1, 50))  # Set ticks every 50 units

            break  # Only plot for the first file with more than 500 chunks
        # # Key Generation Delay (only if chunks > 500)
        # for file_name in file_names:
        #     cur = mysql.connection.cursor()
        #     cur.execute("""
        #         SELECT chunk_index, delay
        #         FROM key_gen_delays
        #         WHERE video_name = %s
        #         ORDER BY chunk_index ASC
        #     """, (file_name,))
        #     key_gen_delays = cur.fetchall()
        #     cur.close()
        #
        #     if len(key_gen_delays) > 500:
        #         chunk_indices = [kgd[0] for kgd in key_gen_delays]
        #         delays = [kgd[1] for kgd in key_gen_delays]
        #
        #         plt.subplot(4, 2, 7)
        #         plt.plot(chunk_indices, delays, '-')
        #         plt.title('Key Generation Delay vs Number of Chunks')
        #         plt.xlabel('Chunk Number')
        #         plt.ylabel('Key Generation Delay (seconds)')
        #         break  # Only plot for the first file with more than 500 chunks
        #     # New Plot: Delay in Generating Encryption Keys vs. Number of Chunks
        #     for file_name in file_names:
        #         cur = mysql.connection.cursor()
        #         cur.execute("""
        #             SELECT chunk_index, delay
        #             FROM key_gen_delays
        #             WHERE video_name = %s
        #             ORDER BY chunk_index ASC
        #         """, (file_name,))
        #         key_gen_delays = cur.fetchall()
        #         cur.close()
        #
        #         if len(key_gen_delays) > 500:
        #             chunk_indices = [kgd[0] for kgd in key_gen_delays]
        #             delays = [kgd[1] for kgd in key_gen_delays]
        #
        #             plt.subplot(4, 2, 8)
        #             plt.plot(chunk_indices, delays, '-')
        #             plt.title('Delay in Generating Encryption Keys vs Number of Chunks')
        #             plt.xlabel('Chunk Number')
        #             plt.ylabel('Key Generation Delay (seconds)')
        #             break  # Only plot for the first file with more than 500 chunks
        # **New Plot 1: Total Processing Time (Encryption + Decryption) vs File Size**
    total_processing_times = [encryption_times[i] + decryption_times[i] for i in range(len(file_sizes))]

    plt.subplot(4, 2, 7)
    plt.plot(file_sizes, total_processing_times, 'o-')
    plt.title('Total Processing Time (Enc + Dec) vs File Size')
    plt.xlabel('File Size (MB)')
    plt.ylabel('Total Processing Time (seconds)')
    plt.xlim(0, x_limit)
    plt.xticks(range(0, x_limit + 1, 50))  # Set ticks every 50 units

    # **New Plot 2: Chunking Efficiency (File Size / Chunking Time)**
    chunking_efficiency = [file_sizes[i] / chunk_times[i] for i in range(len(file_sizes))]
    print('file sizes are ', file_sizes, 'chunk times are ', chunk_times, '\n and chunking efficince is ',
          chunking_efficiency)

    plt.subplot(4, 2, 8)
    plt.plot(file_sizes, chunking_efficiency, 'o-')
    plt.title('Chunking Efficiency (File Size / Chunking Time)')
    plt.xlabel('File Size (MB)')
    plt.ylabel('Chunking Efficiency (MB/second)')
    plt.xlim(0, x_limit)
    plt.xticks(range(0, x_limit + 1, 50))  # Set ticks every 50 units

    plt.tight_layout(rect=(0, 0, 1, 0.96))  # Corrected tight_layout parameters
    user_metrics_folder = os.path.join('static', 'plots', username, 'metrics')
    if not os.path.exists(user_metrics_folder):
        os.makedirs(user_metrics_folder)
    # Save the plot in the user-specific folder
    plot_path = os.path.join(user_metrics_folder, 'metrics_plot.png')
    plt.savefig(plot_path)
    plt.close()

    return render_template('metrics.html', plot_url=plot_path)


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)

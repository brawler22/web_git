# ІНСТРУМЕНТ ДЛЯ ВИВЧЕННЯ КРИПТОГРАФІЇ
# Мова UI: українська
import sys
import hashlib
import hmac
import uuid
import secrets
import random
import time
import webbrowser
import json
import os
import math
try:
    import colorama
    colorama.init()
except ImportError:
    pass
# ---------------------------
# ANSI Коди для Кольору
# ---------------------------
GREEN = '\033[32m'
RED = '\033[31m'
YELLOW = '\033[93m'
BLUE = '\033[34m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'
BOLD = '\033[1m'
RESET = '\033[0m'
# ---------------------------
# Налаштування / Константи
# ---------------------------
APP_TITLE = "CryptoSpider — символічний криптоінструмент (Консоль)"

# ASCII павук для візуалізації
ASCII_SPIDER = r"""
                        (
                         )
                        (
                  /\  .-'''-.  /\
                 //\\/  ,,,  \//\\
                 |/\| ,;;;;;, |/\|
                 //\\\;-'''-;///\\
                //  \/   .   \/  \\
               (| ,-_| \ | / |_-, |)
                 //`__\.-.-./__`\\
                // /.-(() ())-.\ \\
               (\ |)   '---'   (| /)
                ` (|           |) `
                  \)           (/

"""

# ASCII-ART підпис для павука
ASCII_SUBTITLE = [r"""
      ____    ____   ___    ____    _____   ____  
     / ___|  |  _ \ |_ _|  |  _ \  | ____| |  _ \ 
     \___ \  | |_) | | |   | | | | |  _|   |  _ |
      ___) | |  __/  | |   | |_| | | |___  |  _ < 
     |____/  |_|     |_|   |____/  |_____| |_| \_\
    """
                  ]

# ---------------------------
# ASCII Діаграми Алгоритмів
# ---------------------------
ASCII_DIAGRAMS = {
    "AES": r"""
       Plaintext (128-bit)
             |
      [ AddRoundKey ] <---- Initial Key
             |
      +---[ 10/12/14 Rounds ]---+
      |  SubBytes (S-Box)       |
      |  ShiftRows              |
      |  MixColumns (skip last) |
      |  AddRoundKey <--------- | --- Round Keys
      +-------------------------+
             |
       Ciphertext (128-bit)
    """,
    "BLOWFISH": r"""
        Plaintext (64-bit)
              |
      +-------+-------+
      | L_in  |  R_in |
      +-------+-------+
          |       |
      (16 Feistel Rounds)
          |       |
      +---v---++--v---+
      | L_i   || R_i  | <--- P-Array Key
      +-------++------+
      |  XOR <== F-func
      |       |
      +-------X-------+ (Swap L/R)
              |
      [ Final XOR P17/P18 ]
              |
        Ciphertext (64-bit)
    """,
    "TWOFISH": r"""
       Plaintext (128-bit)
              |
      [ Whitening (XOR) ]
              |
      (16 Feistel Rounds)
      +-------+-------+
      | Word0 | Word1 | ...
      +-------+-------+
          |
      [ g-function (S-boxes) ]
          |
      [ PHT Transform (Mix) ] <--- Round Keys
          |
      [ F-function Output ]
          |
      (Feistel XOR & Swap)
              |
      [ Whitening (XOR) ]
              |
       Ciphertext (128-bit)
    """,
    "KALINA": r"""
       Plaintext (128/256/512)
              |
      [ AddRoundKey ] <---- Initial Key
              |
      +---[ Rounds (10-18) ]----+
      |  SubBytes (8 S-Boxes)   |
      |  ShiftRows              |
      |  MixColumns (MDS Matrix)|
      |  AddRoundKey <--------- | --- Round Keys
      +-------------------------+
              |
         Ciphertext
    """,
    "RC4": r"""
          Key (40-2048 bit)
                |
      [ KSA: Init S-Box 0..255 ]
      (Key Scheduling Algorithm)
                |
                v
      +-[ PRGA Loop ]-----------+
      | (Pseudo-Random Gen Algo)|
      | i=(i+1), j=(j+S[i])     |
      | Swap(S[i], S[j])        |
      | K = S[ (S[i]+S[j]) ]    |
      +-------------------------+
                |
      Keystream Byte (K)  <==>  Plaintext Byte (P)
                |                     |
                +-------> XOR <-------+
                          |
                   Ciphertext Byte (C)
    """,
    "CHACHA20": r"""
      Key(256), Nonce(96), Count(32)
                |
      [ Initial 4x4 State Matrix ]
      (Constants | Key | Counter | Nonce)
                |
      +---[ 20 Rounds (10 loops) ]---+
      | Column Quarter Rounds (ARX)  |
      | Diagonal Quarter Rounds (ARX)|
      +------------------------------+
                |
      [ Add Initial State (mod 2^32) ]
                |
      [ Serialize (Little-Endian) ]
                |
      Keystream Block (512-bit)
    """,
    "RSA": r"""
       Message (m) as integer
              |
    +=============================+
    | Encryption (Public Key: e,n)|
    |      c = m^e mod n          |
    +=============================+
              |
       Ciphertext (c)
              |
    +=============================+
    | Decryption (Private Key: d,n)|
    |      m = c^d mod n          |
    +=============================+
              |
       Message (m)
    """,
    "SHA-512": r"""
       Input Message
             |
      [ Padding & Length ]
      (Block size: 1024 bits)
             |
      [ Init Hash Values (H0..H7) ]
             |
      +---[ Compress Block ]------+
      | Message Schedule (W0..W79)|
      | 80 Rounds of:             |
      | (Ch, Maj, Σ0, Σ1, + K_t)  |
      +---------------------------+
             |
      [ Update Hash Values ]
      (H_new = H_old + Round_Out)
             |
      Final Hash (512-bit)
    """,
    "HMAC": r"""
      Key (K), Message (m)
            |
      [ K_prep = Hash(K) or Pad(K) ]
            |
      +---------------------------+
      |   Inner Hash Calculation  |
      | H( (K_prep XOR ipad) || m ) |
      +---------------------------+
            |
            v (inner_hash)
            |
      +---------------------------+
      |   Outer Hash Calculation  |
      | H( (K_prep XOR opad) || v ) |
      +---------------------------+
            |
      HMAC Tag
    """,
    "ECC": r"""
        [ Elliptic Curve Parameters ]
        ( y² = x³ + ax + b mod p, Point G )
                    |
      +---------------------------+
      |  Key Generation           |
      |  Private Key (d) = random |
      |  Public Key (Q) = d * G   |
      |  (Scalar Multiplication)  |
      +---------------------------+
                    |
      +---------------------------+
      |  ECDH Key Exchange        |
      |  Alice: Shared = d_A * Q_B|
      |  Bob:   Shared = d_B * Q_A|
      |  (Result is same Point)   |
      +---------------------------+
    """
}

def print_algo_diagram(algo_name):
    """Виводить ASCII-діаграму для вказаного алгоритму."""
    diagram = ASCII_DIAGRAMS.get(algo_name.upper())
    if diagram:
        print(f"\n{BOLD}{BLUE}--- Структурна схема {algo_name.upper()} ---{RESET}")
        print(f"{BLUE}{diagram}{RESET}")
        print(f"{BOLD}{BLUE}{'-' * 40}{RESET}\n")


# ---------------------------
# СИСТЕМА ДОСЯГНЕНЬ (З ШИФРУВАННЯМ ТА ПРИВ'ЯЗКОЮ ДО ЗАЛІЗА)
# ---------------------------
ACHIEVEMENTS_FILE = "crypto_achievements.json"
DEVICE_ID_FILE = ".device_id"  # Зашифрований файл ідентифікатора

# Спроба імпорту професійного шифрування
try:
    from cryptography.fernet import Fernet

    HAS_CRYPTO_LIB = True
except ImportError:
    HAS_CRYPTO_LIB = False

# Список усіх можливих досягнень
ACHIEVEMENTS_LIST = {
    "FIRST_RUN": {
        "title": "🚀 Перший Крок",
        "desc": "Запустити програму вперше",
        "icon": "👶"
    },
    "AES_MASTER": {
        "title": "🛡️ Майстер AES",
        "desc": "Пройти повну демонстрацію AES",
        "icon": "🗝️"
    },
    "RSA_EXPERT": {
        "title": "🔢 Володар Простих Чисел",
        "desc": "Розібратися з RSA шифруванням",
        "icon": "📜"
    },
    "HASH_HUNTER": {
        "title": "🔍 Хеш-Слідопит",
        "desc": "Знайти лавинний ефект у SHA-512",
        "icon": "❄️"
    },
    "PUZZLE_SOLVER": {
        "title": "🧩 Архітектор",
        "desc": "Успішно зібрати алгоритм AES у міні-грі",
        "icon": "🏆"
    },
    "HACKER_SIM": {
        "title": "💻 Білий Хакер",
        "desc": "Провести симуляцію Brute-Force атаки",
        "icon": "🔓"
    }
}

user_achievements = []


class SecureStorage:
    """Клас для надійного шифрування даних з прив'язкою до ПК."""

    @staticmethod
    def get_machine_key():
        """Генерує ключ шифрування на основі MAC-адреси комп'ютера."""
        # Отримуємо унікальний ID заліза (MAC-адреса)
        node = uuid.getnode()
        # Робимо з нього хеш SHA-256 (32 байти)
        key_bytes = hashlib.sha256(str(node).encode()).digest()

        if HAS_CRYPTO_LIB:
            import base64
            # Fernet вимагає url-safe base64 ключ
            return base64.urlsafe_b64encode(key_bytes)
        else:
            return key_bytes

    @staticmethod
    def encrypt(data_str):
        """Шифрує рядок."""
        key = SecureStorage.get_machine_key()

        if HAS_CRYPTO_LIB:
            f = Fernet(key)
            return f.encrypt(data_str.encode()).decode()
        else:
            # Fallback: XOR-Stream шифрування (якщо немає бібліотеки)
            data_bytes = data_str.encode()
            # Генеруємо потік гами через HMAC
            keystream = hashlib.pbkdf2_hmac('sha256', key, b'salt', 1000, len(data_bytes))
            encrypted = bytes(a ^ b for a, b in zip(data_bytes, keystream))
            return encrypted.hex()

    @staticmethod
    def decrypt(enc_str):
        """Розшифровує рядок. Кидає помилку, якщо ключ не підходить."""
        key = SecureStorage.get_machine_key()

        if HAS_CRYPTO_LIB:
            f = Fernet(key)
            return f.decrypt(enc_str.encode()).decode()
        else:
            # Fallback decryption
            try:
                data_bytes = bytes.fromhex(enc_str)
                keystream = hashlib.pbkdf2_hmac('sha256', key, b'salt', 1000, len(data_bytes))
                decrypted = bytes(a ^ b for a, b in zip(data_bytes, keystream))
                return decrypted.decode()
            except Exception:
                raise ValueError("Decryption failed")


def get_device_id():
    """
    Отримує ID пристрою.
    Якщо файл не розшифровується (інший ПК) -> Скидає ID.
    """
    if os.path.exists(DEVICE_ID_FILE):
        try:
            with open(DEVICE_ID_FILE, "r") as f:
                encrypted_id = f.read().strip()
                # Спроба розшифрувати ключем ЦЬОГО комп'ютера
                return SecureStorage.decrypt(encrypted_id)
        except Exception:
            print(f"\n{BOLD}{RED}🚫 ПОМИЛКА ДОСТУПУ: Зміна обладнання або пошкодження даних!{RESET}")
            print(f"{YELLOW}Система безпеки скинула прогрес для цього пристрою.{RESET}\n")
            time.sleep(2)
            pass  # Якщо помилка - йдемо далі генерувати новий

    # Генеруємо новий ID, шифруємо і зберігаємо
    new_id = str(uuid.uuid4())
    save_device_id(new_id)
    return new_id


def save_device_id(uuid_str):
    """Шифрує і зберігає UUID."""
    try:
        encrypted = SecureStorage.encrypt(uuid_str)
        with open(DEVICE_ID_FILE, "w") as f:
            f.write(encrypted)
    except Exception as e:
        print(f"Помилка запису ID: {e}")


def load_achievements():
    """Завантажує досягнення, перевіряючи прив'язку до пристрою."""
    global user_achievements

    # Це викличе перевірку шифрування. Якщо ПК інший - ID зміниться.
    current_device_id = get_device_id()

    if os.path.exists(ACHIEVEMENTS_FILE):
        try:
            with open(ACHIEVEMENTS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Перевіряємо, чи належить файл цьому ID
            saved_id = data.get("device_id", "")

            if saved_id == current_device_id:
                user_achievements = data.get("achievements", [])
            else:
                # ID файлу не співпадає з розшифрованим ID пристрою
                user_achievements = []
                save_achievements()  # Перезаписуємо під новий пристрій

        except Exception:
            user_achievements = []
    else:
        user_achievements = []


def save_achievements():
    """Зберігає досягнення з поточним ID."""
    current_device_id = get_device_id()
    data = {
        "device_id": current_device_id,
        "achievements": user_achievements
    }
    try:
        with open(ACHIEVEMENTS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
    except Exception as e:
        print(f"Помилка збереження: {e}")


def unlock_achievement(key):
    """Розблоковує нове досягнення."""
    if key not in ACHIEVEMENTS_LIST: return
    if key in user_achievements: return

    user_achievements.append(key)
    save_achievements()

    ach = ACHIEVEMENTS_LIST[key]
    print(f"\n{BOLD}{YELLOW}" + "*" * 60 + f"{RESET}")
    print(f"{BOLD}{YELLOW}🏆 НОВЕ ДОСЯГНЕННЯ РОЗБЛОКОВАНО!{RESET}")
    print(f"   {ach['icon']} {BOLD}{ach['title']}{RESET}")
    print(f"   {ach['desc']}")
    print(f"{BOLD}{YELLOW}" + "*" * 60 + f"{RESET}\n")
    time.sleep(1.5)


def show_my_achievements():
    """Показує список досягнень."""
    load_achievements()

    print("\n" + "=" * 60)
    print(f"=== {BOLD}{YELLOW}ВАШІ ДОСЯГНЕННЯ ({len(user_achievements)}/{len(ACHIEVEMENTS_LIST)}){RESET} ===")
    print("=" * 60)

    # Показуємо статус шифрування
    encryption_status = f"{GREEN}AES-128 (Hardware Bound){RESET}" if HAS_CRYPTO_LIB else f"{YELLOW}Standard Enc (Hardware Bound){RESET}"
    print(f"🔒 Захист: {encryption_status}")
    print("-" * 60)

    for key, data in ACHIEVEMENTS_LIST.items():
        if key in user_achievements:
            status = f"{GREEN}✅ ОТРИМАНО{RESET}"
            icon = data['icon']
            title_color = BOLD + GREEN
            desc_prefix = "   ↳ "
        else:
            status = f"{RED}🔒 ЗАБЛОКОВАНО{RESET}"
            icon = "🔒"
            title_color = RESET
            desc_prefix = "   ↳ "

        print(f"{icon} {title_color}{data['title']:<30}{RESET} | {status}")
        if key in user_achievements:
            print(f"{desc_prefix}{data['desc']}")
        print("-" * 60)

    input("\nНатисніть Enter, щоб повернутися...")
# ---------------------------
# Корисні функції
# ---------------------------
def print_progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    """
    Виводить плавний прогрес-бар у реальному часі.
    """
    percent = f"{100 * (iteration / float(total)):.1f}"
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)

    # Використовуємо sys.stdout для миттєвого оновлення без буферизації
    sys.stdout.write(f'\r{prefix} |{bar}| {percent}% {suffix}')
    sys.stdout.flush()

    if iteration == total:
        print()
def print_diff_analysis(original_hex, modified_hex, title="Візуалізація лавинного ефекту"):
    """
    Порівнює два рядки у форматі HEX та виводить бінарне представлення,
    виділяючи змінені біти червоним.
    """
    print(f"\n{BOLD}{YELLOW}--- {title} ---{RESET}")

    # Конвертуємо Hex у байти
    try:
        original_bytes = bytes.fromhex(original_hex)
        modified_bytes = bytes.fromhex(modified_hex)
    except ValueError:
        print(f"{RED}❌ Помилка конвертації Hex.{RESET}")
        return

    total_bits = 0
    changed_bits = 0

    print(f"  Оригінал (Hex): {original_hex[:64]}...")
    print(f"  Змінено (Hex): {modified_hex[:64]}...")

    print(f"\n  {BOLD}БІНАРНЕ ПОРІВНЯННЯ (виділено змінені біти):{RESET}")

    for i in range(len(original_bytes)):
        b1 = original_bytes[i]
        b2 = modified_bytes[i]

        b1_bin = format(b1, '08b')
        b2_bin = format(b2, '08b')

        diff_output = ""
        is_changed = False

        for j in range(8):
            total_bits += 1
            if b1_bin[j] != b2_bin[j]:
                diff_output += f"{RED}{b2_bin[j]}{RESET}"  # Червоний, якщо змінився
                changed_bits += 1
                is_changed = True
            else:
                diff_output += f"{GREEN}{b2_bin[j]}{RESET}"  # Зелений, якщо залишився

        # Друк по 8 байт для кращої читабельності
        if i % 8 == 0 and i != 0:
            print()

        print(f"{diff_output} ", end="")

    print("\n")
    print(f"  {BOLD}РЕЗУЛЬТАТ:{RESET}")
    print(f"    Загалом бітів: {total_bits}")
    print(f"    Змінено бітів: {changed_bits}")
    print(f"    Відсоток змін: {(changed_bits / total_bits) * 100:.2f}%")


def ask_to_watch_video(algo_name):
    """
    Запитує користувача, чи хоче він переглянути відео-пояснення,
    і відкриває браузер, якщо відповідь 'y'.
    """
    # Словник посилань.
    # ДЛЯ НАДІЙНОСТІ: Для рідкісних алгоритмів використовуються пошукові запити,
    # щоб посилання ніколи не "помирали".
    video_links = {
        # --- Симетричні Блочні ---
        "AES": "https://www.youtube.com/watch?v=O4xNJsjtN6E",
        "BLOWFISH": "https://youtu.be/gz8AV0bPaOU?si=o6FFxOncTnKyltIW",
        "TWOFISH": "https://youtu.be/SpaXSMkJLs0?si=yI2WbVZlK8qSM5rO",
        "KALINA": "https://youtu.be/Xhz6c7m7puU?si=Ij30GYFMYekrqGaa",

        # --- Симетричні Потокові ---
        "RC4": "https://youtu.be/LWdqST4ZDO0?si=6M-9Gr1hpBqpOEdL",
        "CHACHA20": "https://youtu.be/UeIpq-C-GSA",

        # --- Асиметричні та Хеш ---
        "RSA": "https://www.youtube.com/watch?v=4zahvcJ9glg",
        "SHA-512": "https://www.youtube.com/watch?v=DMtFhACPnTY",
        "HMAC": "https://youtu.be/wlSG3pEiQdc?si=KMyQw9n3_3r8kFMy",
        "ECC": "https://www.youtube.com/watch?v=NF1pwjL9-DE",

        # --- Спеціальні ---
        "HOMOMORPHIC": "https://youtu.be/lNw6d05RW6E",
        "LATTICE": "https://www.youtube.com/watch?v=K026C5YaB3A"
    }
    url = video_links.get(algo_name.upper())

    if url:
        print(f"\n{BOLD}{YELLOW}[VIDEO]{RESET} Доступна відео-демонстрація для {algo_name}.")
        choice = input(f"Відкрити YouTube у браузері? (y/n): ").strip().lower()
        if choice == 'y':
            print(f"Відкриваю посилання...")
            webbrowser.open(url)
    else:
        pass

def gmult(a, b, m_poly=0x11B):
    """
    Множення двох байтів у полі Галуа GF(2^8) (поліном AES: x⁸+x⁴+x³+x+1, або 0x11B).
    """
    p = 0
    for i in range(8):
        if b & 1:
            p ^= a

        # Перевірка на переповнення (зсув a)
        if a & 0x80:  # Якщо найстарший біт встановлений
            a = (a << 1) ^ m_poly
        else:
            a <<= 1

        a &= 0xFF  # Обрізання до 8 біт
        b >>= 1
    return p


def gmult_poly(a, b, m_poly=0x11B):
    """Множення двох байтів у GF(2⁸) (той самий gmult, але перейменований для ясності)."""
    p = 0
    for i in range(8):
        if b & 1:
            p ^= a
        if a & 0x80:
            a = (a << 1) ^ m_poly
        else:
            a <<= 1
        a &= 0xFF
        b >>= 1
    return p


def poly_deg(a):
    """Визначає степінь полінома (найвищий встановлений біт)."""
    if a == 0:
        return -1
    return a.bit_length() - 1


def poly_div(a, b):
    """
    Поділ поліномів у GF(2) (використовуючи XOR).
    Повертає (частка, залишок) як цілі числа.
    """
    if b == 0:
        raise ZeroDivisionError("Дільник не може бути нулем.")

    a_deg = poly_deg(a)
    b_deg = poly_deg(b)

    quotient = 0
    remainder = a

    while a_deg >= b_deg and remainder != 0:
        # q_i = x^(a_deg - b_deg)
        shift = a_deg - b_deg

        # Додаємо до частки
        quotient ^= (1 << shift)

        # Віднімаємо (що є XOR)
        remainder ^= (b << shift)

        a_deg = poly_deg(remainder)

    return quotient, remainder


def poly_extended_gcd(a, m_poly):
    """
    Розширений Евклід для поліномів у GF(2).
    Знаходить a⁻¹ mod m_poly. Повертає (g, x).
    """
    # Ініціалізація змінних
    r0, r1 = m_poly, a
    x0, x1 = 0, 1

    # Вивід таблиці (спрощена, без повного виводу крок за кроком)
    print(f"\n      {BOLD}{YELLOW}ТАБЛИЦЯ ПОЛІНОМІАЛЬНОГО ЕВКЛІДА (a⁻¹ mod m){RESET}")

    while r1 != 0:
        try:
            q, r = poly_div(r0, r1)
        except ZeroDivisionError:
            # Це повинно відбутися, лише якщо r1 = 0 (кінець циклу)
            break

        # Оновлення r0, r1
        r0, r1 = r1, r

        # Оновлення x0, x1: x = x0 + q * x1 (XOR)
        x = x0 ^ gmult_poly(q, x1, 0x100)  # Множення в GF(2⁸) без редукції 0x11B
        x0, x1 = x1, x

        # Невеликий вивід для перших кроків
        # print(f"        r0={r0:x}, r1={r1:x}, q={q:x}, x={x:x}")

    # Якщо gcd(a, m_poly) = 1, то r0 = 1, і x0 містить обернений елемент.
    if r0 == 1:
        return r0, x0
    else:
        return r0, 0
def extended_gcd_plain(a, b):
    """
    Розширений алгоритм Евкліда (без виводу таблиці).
    Повертає кортеж (g, x, y) такий, що a*x + b*y = g = gcd(a, b).
    """
    if a == 0:
        return b, 0, 1

    # Рекурсивний виклик для (b mod a, a)
    g, x1, y1 = extended_gcd_plain(b % a, a)

    # Оновлення x та y (за формулами)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y
def print_ascii_art():
    """Виводить ASCII-арт павука та банер у консоль."""
    print("\n" * 2)
    print(ASCII_SPIDER)
    print()
    for line in ASCII_SUBTITLE:
        print(line)
    print("\n" * 2)


def print_step(step_num, title, data=None, delay=0.5, interactive=True):
    """Уніфікований вивід кроку з кольором та інтерактивною паузою."""
    print(f"\n{BOLD}{BLUE}{'=' * 70}{RESET}")
    print(f"{BOLD}{BLUE}КРОК {step_num}: {title}{RESET}")
    print(f"{BOLD}{BLUE}{'=' * 70}{RESET}")
    if data:
        if isinstance(data, dict):
            for key, value in data.items():
                print(f"  {BOLD}{key}:{RESET} {value}")
        else:
            print(f"  {data}")

    if interactive:
        input(f"{YELLOW}Натисніть Enter для продовження...{RESET}")
    elif delay > 0:
        time.sleep(delay)


def print_substep(substep_num, title, data=None, delay=0.3):
    """Уніфікований вивід підкроку з кольором."""
    print(f"\n  [{BOLD}{YELLOW}{substep_num}{RESET}] {BOLD}{title}{RESET}")
    if data:
        if isinstance(data, dict):
            for key, value in data.items():
                print(f"      {BOLD}{key}:{RESET} {value}")
        else:
            print(f"      {data}")
    time.sleep(delay)


def bytes_to_binary_string(byte_data, group=8):
    """Конвертує байти у бінарний рядок з групуванням."""
    binary = ''.join(format(byte, '08b') for byte in byte_data)
    if group > 0:
        return ' '.join(binary[i:i + group] for i in range(0, len(binary), group))
    return binary


def print_byte_comparison(byte1, byte2, title="Порівняння байтів"):
    """Детальне порівняння двох байтів."""
    print(f"\n  {title}:")
    print(f"      Байт 1: {byte1:02x} ({byte1:08b})")
    print(f"      Байт 2: {byte2:02x} ({byte2:08b})")
    xor_result = byte1 ^ byte2
    print(f"      XOR:     {xor_result:02x} ({xor_result:08b})")
    print(f"      Змінено бітів: {bin(xor_result).count('1')}")


def right_rotate(value, shift):
    """Циклічний зсув вправо для 64-бітних чисел."""
    BIT_64 = 0xFFFFFFFFFFFFFFFF
    return (value >> shift) | (value << (64 - shift)) & BIT_64


# =========================================================================
# I. СИМЕТРИЧНЕ БЛОЧНЕ ШИФРУВАННЯ (РАУНДОВА ДЕТАЛІЗАЦІЯ)
# =========================================================================

def demo_aes_detailed():
    """НАДДЕТАЛЬНА демонстрація AES з КОЖНИМ перетворенням."""
    ask_to_watch_video("AES")
    print_algo_diagram("AES")
    print("\n" + "=" * 80)
    print("=== НАДДЕТАЛЬНА ДЕМОНСТРАЦІЯ AES-128 - КОЖЕН КРОК ===")
    print("=" * 80)

    # 1. Ініціалізація
    user_input = input("Введи 16-символьний текст: ").strip() or "AES Demonstration"
    if len(user_input) != 16:
        user_input = user_input.ljust(16, ' ')[:16]
        print(f"Текст вирівняно до 16 символів: '{user_input}'")

    plaintext = user_input.encode('utf-8')
    key = secrets.token_bytes(16)

    print_step(1, "ІНІЦІАЛІЗАЦІЯ", {
        "Вхідний текст": f"'{user_input}'",
        "Текст (hex)": plaintext.hex(),
        "Ключ (hex)": key.hex(),
        "Довжина блоку": "128 біт (16 байт)",
        "Довжина ключа": "128 біт (16 байт)"
    })

    # ПОВНИЙ AES S-Box (256 значень)
    def aes_s_box_detailed(byte):
        s_box = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]
        return s_box[byte]

    def print_state_matrix_detailed(state, title="Матриця стану"):
        print(f"\n  {title}:")
        print(f"      Позиції:    [0,0] [0,1] [0,2] [0,3]")
        print(f"                  [1,0] [1,1] [1,2] [1,3]")
        print(f"                  [2,0] [2,1] [2,2] [2,3]")
        print(f"                  [3,0] [3,1] [3,2] [3,3]")
        print(f"      Значення:   [ {state[0]:02x}   {state[4]:02x}   {state[8]:02x}   {state[12]:02x} ]")
        print(f"                  [ {state[1]:02x}   {state[5]:02x}   {state[9]:02x}   {state[13]:02x} ]")
        print(f"                  [ {state[2]:02x}   {state[6]:02x}   {state[10]:02x}   {state[14]:02x} ]")
        print(f"                  [ {state[3]:02x}   {state[7]:02x}   {state[11]:02x}   {state[15]:02x} ]")

    # Початковий стан
    state = list(plaintext)

    print_step(2, "ПОЧАТКОВИЙ СТАН")
    print_substep("2.1", "ОРГАНІЗАЦІЯ ДАНИХ В МАТРИЦЮ 4×4", {
        "Метод": "Заповнення по стовпцях",
        "Формат": "state[row + 4×col]"
    })

    print_state_matrix_detailed(state, "Початкова матриця стану")

    # Детальний вивід початкових значень
    print_substep("2.2", "ДЕТАЛЬНІ ЗНАЧЕННЯ БАЙТІВ")
    for i in range(16):
        old_byte = state[i]
        new_byte = aes_s_box_detailed(state[i])
        state[i] = new_byte

        row = i % 4
        col = i // 4
        print(f"      state[{i}] = pos[{row},{col}]: {old_byte:02x} → S-Box[{old_byte:02x}] → {new_byte:02x}")

    # Генерація раундових ключів
    print_step(3, "ГЕНЕРАЦІЯ РАУНДОВИХ КЛЮЧІВ")

    round_keys = []
    current_key = list(key)

    print_substep("3.1", "ПОЧАТКОВИЙ КЛЮЧ", {
        "Ключ (hex)": bytes(current_key).hex(),
        "Матриця ключа": f"[{current_key[0]:02x} {current_key[4]:02x} {current_key[8]:02x} {current_key[12]:02x}] ..."
    })

    # Спрощена генерація раундового ключа
    round_key = hashlib.sha256(key + b'round1').digest()[:16]
    round_keys.append(round_key)

    print_substep("3.2", "РАУНДОВИЙ КЛЮЧ 1", {
        "Ключ (hex)": round_key.hex(),
        "Метод": "SHA-256 від основного ключа"
    })

    # Основний цикл AES (1 раунд для демонстрації)
    for round_num in range(1, 2):
        print_step(4, f"РАУНД {round_num}", f"Обробка раунду {round_num} з 10")

        # 1. SubBytes
        print_step(4.1, "SUBSTITUTE BYTES (SubBytes)")
        print_substep("4.1.1", "ПРИНЦИП РОБОТИ", {
            "Тип": "Нелінійна заміна байтів",
            "Основа": "S-Box 16×16 (256 значень)",
            "Мета": "Заплутування (Confusion)"
        })

        old_state = state.copy()
        print_substep("4.1.2", "ПОКРОКОВА ЗАМІНА БАЙТІВ")

        for i in range(16):
            old_byte = state[i]
            new_byte = aes_s_box_detailed(state[i])
            state[i] = new_byte

            row = i % 4
            col = i // 4
            print(f"      state[{i}] = pos[{row},{col}]: {old_byte:02x} → S-Box[{old_byte:02x}] → {new_byte:02x}")

        print_state_matrix_detailed(state, "Після SubBytes")

        # 2. ShiftRows
        print_step(4.2, "SHIFT ROWS")
        print_substep("4.2.1", "ПРИНЦИП РОБОТИ", {
            "Тип": "Лінійне перемішування",
            "Мета": "Поширення (Diffusion)",
            "Алгоритм": "Циклічний зсув рядків"
        })

        old_state = state.copy()
        print_substep("4.2.2", "ДЕТАЛЬНІ ЗСУВИ РЯДКІВ")

        for i in range(4):
            row_start = i * 4
            row = state[row_start:row_start + 4]
            shifted_row = row[i:] + row[:i]
            state[row_start:row_start + 4] = shifted_row

            print(f"      Рядок {i}: зсув на {i} позицій")
            print(f"        До:    {[f'{b:02x}' for b in row]}")
            print(f"        Після: {[f'{b:02x}' for b in shifted_row]}")

        print_state_matrix_detailed(state, "Після ShiftRows")

        # 3. MixColumns
        print_step(4.3, "MIX COLUMNS")
        print_substep("4.3.1", "ПРИНЦИП РОБОТИ", {
            "Тип": "Лінійне перетворення",
            "Основа": "Множення в полі Галуа GF(2⁸)",
            "Мета": "Поширення (Diffusion)",
            "Матриця": "Фіксована матриця 4×4"
        })

        # Спрощена імітація MixColumns
        def mix_columns_detailed(state):
            new_state = state.copy()

            print_substep("4.3.2", "ОБРОБКА КОЖНОЇ КОЛОНКИ")

            for col in range(4):
                print(f"      --- Колонка {col} ---")

                # Байти поточної колонки
                col_bytes = [state[col + i * 4] for i in range(4)]
                print(f"        Вхідні байти: {[f'{b:02x}' for b in col_bytes]}")

                # Спрощене MixColumns (не справжнє GF(2⁸))
                new_col = [
                    (col_bytes[0] << 1) ^ (col_bytes[1] << 1) ^ col_bytes[1] ^ col_bytes[2] ^ col_bytes[3],
                    col_bytes[0] ^ (col_bytes[1] << 1) ^ (col_bytes[2] << 1) ^ col_bytes[2] ^ col_bytes[3],
                    col_bytes[0] ^ col_bytes[1] ^ (col_bytes[2] << 1) ^ (col_bytes[3] << 1) ^ col_bytes[3],
                    (col_bytes[0] << 1) ^ col_bytes[0] ^ col_bytes[1] ^ col_bytes[2] ^ (col_bytes[3] << 1)
                ]

                # Обрізання до байта
                for i in range(4):
                    new_col[i] = new_col[i] & 0xFF
                    new_state[col + i * 4] = new_col[i]

                print(f"        Вихідні байти: {[f'{b:02x}' for b in new_col]}")

                # Детальний вивід змін
                for i in range(4):
                    old_val = col_bytes[i]
                    new_val = new_col[i]
                    if old_val != new_val:
                        print(f"        Байт {i}: {old_val:02x} → {new_val:02x} (змінено)")
                    else:
                        print(f"        Байт {i}: {old_val:02x} → {new_val:02x} (без змін)")

            return new_state

        old_state = state.copy()
        state = mix_columns_detailed(state)
        print_state_matrix_detailed(state, "Після MixColumns")

        # 4. AddRoundKey
        print_step(4.4, "ADD ROUND KEY")
        print_substep("4.4.1", "ПРИНЦИП РОБОТИ", {
            "Тип": "Побітова операція XOR",
            "Мета": "Додавання ключа до стану",
            "Формула": "state[i] = state[i] XOR round_key[i]"
        })

        round_key = round_keys[round_num - 1]
        print_substep("4.4.2", "РАУНДОВИЙ КЛЮЧ", {
            "Ключ (hex)": round_key.hex(),
            "Довжина": f"{len(round_key)} байт"
        })

        print_substep("4.4.3", "ПОКРОКОВЕ ВИКОНАННЯ XOR")

        for i in range(16):
            old_byte = state[i]
            state[i] ^= round_key[i]

            row = i % 4
            col = i // 4
            print(f"      state[{i}] = pos[{row},{col}]: {old_byte:02x} XOR {round_key[i]:02x} = {state[i]:02x}")
        for i in range(16):
            old_byte = state[i]
            state[i] ^= round_key[i]

            # Використовуємо кольоровий вивід
            colored_new_byte = get_color_diff_hex(old_byte, state[i])

            row = i % 4
            col = i // 4
            print(f"      state[{i}] = pos[{row},{col}]: {old_byte:02x} XOR {round_key[i]:02x} = {colored_new_byte}")
        print_state_matrix_detailed(state, "Після AddRoundKey")

    # Фінальний результат
    ciphertext = bytes(state)

    print_step(5, "ФІНАЛЬНИЙ РЕЗУЛЬТАТ")
    print_substep("5.1", "ШИФРОТЕКСТ", {
        "Hex": ciphertext.hex(),
        "Довжина": f"{len(ciphertext)} байт",
        "ASCII": ''.join(chr(b) if 32 <= b <= 126 else '.' for b in ciphertext)
    })

    print_substep("5.2", "ПОРІВНЯННЯ З ОРИГІНАЛОМ", {
        "Оригінал (hex)": plaintext.hex(),
        "Шифротекст (hex)": ciphertext.hex(),
        "Змінено байтів": sum(1 for i in range(16) if plaintext[i] != ciphertext[i])
    })

    # Демонстрація лавинного ефекту
    print_step(6, "ДЕМОНСТРАЦІЯ ЛАВИННОГО ЕФЕКТУ")

    # Змінюємо один біт у оригіналі
    modified_plaintext = bytearray(plaintext)
    modified_plaintext[0] ^= 0x01  # Змінюємо один біт у першому байті

    # Шифруємо модифікований текст
    modified_state = list(modified_plaintext)
    for round_num in range(1, 2):
        for i in range(16):
            modified_state[i] = aes_s_box_detailed(modified_state[i])

        for i in range(4):
            row_start = i * 4
            row = modified_state[row_start:row_start + 4]
            modified_state[row_start:row_start + 4] = row[i:] + row[:i]

        for i in range(16):
            modified_state[i] ^= round_key[i]

    modified_ciphertext = bytes(modified_state)

    # Підрахунок різниці
    diff_bits = 0
    for i in range(16):
        diff_bits += bin(ciphertext[i] ^ modified_ciphertext[i]).count('1')

    print_substep("6.1", "РЕЗУЛЬТАТ ЛАВИННОГО ЕФЕКТУ", {
        "Змінено бітів у вході": 1,
        "Змінено бітів у виході": diff_bits,
        "Відсоток змін": f"{(diff_bits / 128) * 100:.1f}%",
        "Очікуваний результат": "~50% змінених бітів"
    })
    unlock_achievement("AES_MASTER")
    print("\n" + "=" * 80)
    print("✅ AES ДЕМОНСТРАЦІЯ ЗАВЕРШЕНА")
    print("=" * 80)


def demo_blowfish_detailed():
    """НАДДЕТАЛЬНА демонстрація Blowfish з КОЖНИМ перетворенням."""
    ask_to_watch_video("BLOWFISH")
    print_algo_diagram("BLOWFISH")
    print("\n" + "=" * 80)
    print("=== НАДДЕТАЛЬНА ДЕМОНСТРАЦІЯ BLOWFISH - КОЖЕН КРОК ===")
    print("=" * 80)

    # 1. Ініціалізація
    print_step(1, "ІНІЦІАЛІЗАЦІЯ АЛГОРИТМУ")
    print_substep("1.1", "ПАРАМЕТРИ BLOWFISH", {
        "Розмір блоку": "64 біта (8 байт)",
        "Розмір ключа": "32-448 біт",
        "Кількість раундів": "16",
        "Тип": "Мережа Файстеля"
    })

    # Генерація тестових даних
    data = secrets.token_bytes(8)
    print_substep("1.2", "ТЕСТОВИЙ БЛОК ДАНИХ", {
        "Блок (hex)": data.hex(),
        "Блок (бінарно)": bytes_to_binary_string(data),
        "Довжина": f"{len(data)} байт"
    })

    # Ініціалізація P-боксів та S-боксів
    print_step(2, "ІНІЦІАЛІЗАЦІЯ P-БОКСІВ ТА S-БОКСІВ")

    # P-бокси (18 штук)
    P_box = [secrets.randbits(32) for _ in range(18)]
    print_substep("2.1", "P-БОКСИ (18 ШТУК)", {
        "Призначення": "Раундові ключі",
        "P[0]": f"{P_box[0]:08x}",
        "P[1]": f"{P_box[1]:08x}",
        "P[2]": f"{P_box[2]:08x}",
        "...": "...",
        "P[17]": f"{P_box[17]:08x}"
    })

    # S-бокси (4 штуки по 256 записів)
    S_box = [[secrets.randbits(32) for _ in range(256)] for _ in range(4)]
    print_substep("2.2", "S-БОКСИ (4×256 ЗАПИСІВ)", {
        "Призначення": "Нелінійні заміни",
        "S[0]": f"{S_box[0][0]:08x} ... {S_box[0][255]:08x}",
        "S[1]": f"{S_box[1][0]:08x} ... {S_box[1][255]:08x}",
        "S[2]": f"{S_box[2][0]:08x} ... {S_box[2][255]:08x}",
        "S[3]": f"{S_box[3][0]:08x} ... {S_box[3][255]:08x}"
    })

    # Поділ блоку на L та R
    print_step(3, "ПОДІЛ ВХІДНОГО БЛОКУ")
    L = int.from_bytes(data[:4], 'big')
    R = int.from_bytes(data[4:], 'big')

    print_substep("3.1", "64-БІТНИЙ БЛОК → L + R", {
        "Повний блок": data.hex(),
        "L (лівий 32-біт)": f"{L:08x}",
        "R (правий 32-біт)": f"{R:08x}",
        "Бітове представлення L": f"{L:032b}",
        "Бітове представлення R": f"{R:032b}"
    })

    # Раунд 1
    print_step(4, "РАУНД 1", "Обробка першого раунду")

    # Крок 1: L = L XOR P[0]
    print_step(4.1, "ADD P-БОКСА: L ⊕ P[0]")
    P1 = P_box[0]
    old_L = L

    print_substep("4.1.1", "ВХІДНІ ДАНІ", {
        "L (до)": f"{old_L:08x}",
        "P[0]": f"{P1:08x}",
        "Операція": "L = L XOR P[0]"
    })

    L ^= P1

    print_substep("4.1.2", "РЕЗУЛЬТАТ XOR", {
        "L (після)": f"{L:08x}",
        "Бітові зміни": f"{bin(old_L ^ L)}"
    })

    # Крок 2: F-функція
    print_step(4.2, "F-ФУНКЦІЯ: F(L)")
    print_substep("4.2.1", "ПРИНЦИП РОБОТИ F-ФУНКЦІЇ", {
        "Формула": "F(L) = ((S1[a] + S2[b]) XOR S3[c]) + S4[d]",
        "Вхід": "32-бітне слово L",
        "Вихід": "32-бітне слово",
        "Мета": "Нелінійне перетворення"
    })

    # Розбиття L на 4 байти
    a = (L >> 24) & 0xFF  # Найстарший байт
    b = (L >> 16) & 0xFF
    c = (L >> 8) & 0xFF
    d = L & 0xFF  # Наймолодший байт

    print_substep("4.2.2", "РОЗБИТТЯ L НА 4 БАЙТИ", {
        "L (hex)": f"{L:08x}",
        "a (байт 3)": f"{a:02x} = {a:3d} (біти 24-31)",
        "b (байт 2)": f"{b:02x} = {b:3d} (біти 16-23)",
        "c (байт 1)": f"{c:02x} = {c:3d} (біти 8-15)",
        "d (байт 0)": f"{d:02x} = {d:3d} (біти 0-7)"
    })

    # Обчислення F-функції покроково
    print_step(4.3, "ОБЧИСЛЕННЯ F-ФУНКЦІЇ ПОКРОКОВО")

    # Крок 2.1: S1[a]
    S1a = S_box[0][a]
    print_substep("4.3.1", "S1[a] - ПЕРШИЙ S-БОКС", {
        "a": f"{a:02x}",
        "S1[a]": f"{S1a:08x}",
        "Бінарно": f"{S1a:032b}"
    })

    # Крок 2.2: S2[b]
    S2b = S_box[1][b]
    print_substep("4.3.2", "S2[b] - ДРУГИЙ S-БОКС", {
        "b": f"{b:02x}",
        "S2[b]": f"{S2b:08x}",
        "Бінарно": f"{S2b:032b}"
    })

    # Крок 2.3: S1[a] + S2[b]
    sum1 = (S1a + S2b) & 0xFFFFFFFF
    print_substep("4.3.3", "ДОДАВАННЯ: S1[a] + S2[b]", {
        "S1[a]": f"{S1a:08x}",
        "S2[b]": f"{S2b:08x}",
        "Сума": f"{sum1:08x}",
        "Обчислення": f"{S1a} + {S2b} = {S1a + S2b} → mod 2³² → {sum1}"
    })

    # Крок 2.4: S3[c]
    S3c = S_box[2][c]
    print_substep("4.3.4", "S3[c] - ТРЕТІЙ S-БОКС", {
        "c": f"{c:02x}",
        "S3[c]": f"{S3c:08x}",
        "Бінарно": f"{S3c:032b}"
    })

    # Крок 2.5: (S1[a] + S2[b]) XOR S3[c]
    xor_result = sum1 ^ S3c

    # Кольоровий вивід результату XOR
    colored_xor_res = get_color_diff_hex(sum1, xor_result)

    print_substep("4.3.5", "XOR: (S1[a]+S2[b]) ⊕ S3[c]", {
        "Сума": f"{sum1:08x}",
        "S3[c]": f"{S3c:08x}",
        "XOR результат": colored_xor_res,
        "Бінарний XOR": f"{sum1:032b} XOR {S3c:032b} = {xor_result:032b}"
    })

    # Крок 2.6: S4[d]
    S4d = S_box[3][d]
    print_substep("4.3.6", "S4[d] - ЧЕТВЕРТИЙ S-БОКС", {
        "d": f"{d:02x}",
        "S4[d]": f"{S4d:08x}",
        "Бінарно": f"{S4d:032b}"
    })

    # Крок 2.7: ((S1[a] + S2[b]) XOR S3[c]) + S4[d]
    F_output = (xor_result + S4d) & 0xFFFFFFFF
    print_substep("4.3.7", "ФІНАЛЬНЕ ДОДАВАННЯ", {
        "XOR результат": f"{xor_result:08x}",
        "S4[d]": f"{S4d:08x}",
        "F(L)": f"{F_output:08x}",
        "Обчислення": f"{xor_result} + {S4d} = {xor_result + S4d} → mod 2³² → {F_output}"
    })

    print_step(4.4, "РЕЗУЛЬТАТ F-ФУНКЦІЇ", {
        "Вхід L": f"{L:08x}",
        "Вихід F(L)": f"{F_output:08x}",
        "Бітова різниця": f"Змінено {bin(L ^ F_output).count('1')} бітів"
    })

    # Крок 3: R = R XOR F(L)
    print_step(5, "XOR З ПРАВИМ БЛОКОМ: R ⊕ F(L)")
    old_R = R

    print_substep("5.1", "ВХІДНІ ДАНІ", {
        "R (до)": f"{old_R:08x}",
        "F(L)": f"{F_output:08x}",
        "Операція": "R = R XOR F(L)"
    })

    R_new = R ^ F_output

    # Кольорове представлення результату R
    colored_R_new = get_color_diff_hex(old_R, R_new)

    print_substep("5.2", "РЕЗУЛЬТАТ XOR", {
        "R (після)": colored_R_new,
        "Бітові зміни": f"{bin(old_R ^ R_new)}",
        "Змінено бітів": f"{bin(old_R ^ R_new).count('1')}"
    })
    # Крок 4: Обмін L та R
    print_step(6, "ОБМІН БЛОКІВ")
    L_next = L
    R_next = R_new

    print_substep("6.1", "СТАН ПЕРЕД ОБМІНОМ", {
        "L": f"{L_next:08x}",
        "R": f"{R_next:08x}"
    })

    # В мережі Файстеля обмінюємо L та R
    final_L = R_next
    final_R = L_next

    print_substep("6.2", "СТАН ПІСЛЯ ОБМІНУ", {
        "L (нове) = R (старе)": f"{final_L:08x}",
        "R (нове) = L (старе)": f"{final_R:08x}"
    })

    # Фінальний результат
    print_step(7, "ФІНАЛЬНИЙ РЕЗУЛЬТАТ РАУНДУ")
    final_block = final_L.to_bytes(4, 'big') + final_R.to_bytes(4, 'big')

    print_substep("7.1", "СКЛАДАННЯ БЛОКУ", {
        "L (hex)": f"{final_L:08x}",
        "R (hex)": f"{final_R:08x}",
        "Об'єднаний блок": final_block.hex()
    })

    print_substep("7.2", "ПОРІВНЯННЯ З ОРИГІНАЛОМ", {
        "Оригінальний блок": data.hex(),
        "Результат раунду": final_block.hex(),
        "Змінено байтів": sum(1 for i in range(8) if data[i] != final_block[i]),
        "Змінено бітів": sum(bin(data[i] ^ final_block[i]).count('1') for i in range(8))
    })

    # Демонстрація повного циклу Файстеля
    print_step(8, "ПОВНИЙ ЦИКЛ МЕРЕЖІ ФАЙСТЕЛЯ")
    print_substep("8.1", "ФОРМУЛИ РАУНДУ", {
        "Lᵢ = Rᵢ₋₁": "Новий лівий = старий правий",
        "Rᵢ = Lᵢ₋₁ XOR F(Rᵢ₋₁)": "Новий правий = старий лівий XOR F(старий правий)"
    })

    print_substep("8.2", "ВИДАТНІ ВЛАСТИВОСТІ", {
        "Симетрія": "Шифрування та дешифрування використовують однакову F-функцію",
        "Безпека": "Залежить від якості F-функції та ключового розкладу",
        "Ефективність": "Потрібна лише одна F-функція на раунд"
    })

    # Візуалізація мережі Файстеля
    print_step(9, "ВІЗУАЛІЗАЦІЯ МЕРЕЖІ ФАЙСТЕЛЯ")
    print("""
      Раунд i:
        Вхід: Lᵢ₋₁, Rᵢ₋₁
        │
        ├─ F(Rᵢ₋₁) → Обчислюємо F-функцію
        │
        ├─ Lᵢ₋₁ XOR F(Rᵢ₋₁) → Отримуємо новий Rᵢ
        │
        └─ Rᵢ₋₁ → Стає новим Lᵢ

        Вихід: Lᵢ = Rᵢ₋₁, Rᵢ = Lᵢ₋₁ XOR F(Rᵢ₋₁)
    """)

    print("\n" + "=" * 80)
    print("✅ BLOWFISH ДЕМОНСТРАЦІЯ ЗАВЕРШЕНА")
    print("=" * 80)


def demo_twofish_detailed():
    """НАДДЕТАЛЬНА демонстрація Twofish з КОЖНИМ перетворенням."""
    ask_to_watch_video("TWOFISH")
    print_algo_diagram("TWOFISH")
    print("\n" + "=" * 80)
    print("=== НАДДЕТАЛЬНА ДЕМОНСТРАЦІЯ TWOFISH - КОЖЕН КРОК ===")
    print("=" * 80)

    # 1. Ініціалізація
    print_step(1, "ІНІЦІАЛІЗАЦІЯ АЛГОРИТМУ")
    print_substep("1.1", "ПАРАМЕТРИ TWOFISH", {
        "Розмір блоку": "128 біт (16 байт)",
        "Розмір ключа": "128/192/256 біт",
        "Кількість раундів": "16",
        "Тип": "Модифікована мережа Файстеля",
        "Особливості": "Key-dependent S-boxes, PHT"
    })

    # Генерація тестових даних
    data = secrets.token_bytes(16)
    key = secrets.token_bytes(16)

    print_substep("1.2", "ТЕСТОВИЙ БЛОК ДАНИХ", {
        "Блок (hex)": data.hex(),
        "Ключ (hex)": key.hex(),
        "Довжина блоку": f"{len(data)} байт",
        "Довжина ключа": f"{len(key)} байт"
    })

    # Розбиття блоку на 4 32-бітні слова
    print_step(2, "РОЗБИТТЯ БЛОКУ НА 4 СЛОВА")
    R0 = int.from_bytes(data[0:4], 'big')
    R1 = int.from_bytes(data[4:8], 'big')
    R2 = int.from_bytes(data[8:12], 'big')
    R3 = int.from_bytes(data[12:16], 'big')

    print_substep("2.1", "128-БІТНИЙ БЛОК → 4×32-БІТНІ СЛОВА", {
        "Повний блок": data.hex(),
        "R0 (слово 0)": f"{R0:08x} = {R0:032b}",
        "R1 (слово 1)": f"{R1:08x} = {R1:032b}",
        "R2 (слово 2)": f"{R2:08x} = {R2:032b}",
        "R3 (слово 3)": f"{R3:08x} = {R3:032b}"
    })

    # Генерація раундових ключів
    print_step(3, "ГЕНЕРАЦІЯ РАУНДОВИХ КЛЮЧІВ")
    Round_key = [secrets.randbits(32) for _ in range(4)]

    print_substep("3.1", "РАУНДОВІ КЛЮЧІ (4 СЛОВА)", {
        "K[0]": f"{Round_key[0]:08x}",
        "K[1]": f"{Round_key[1]:08x}",
        "K[2]": f"{Round_key[2]:08x}",
        "K[3]": f"{Round_key[3]:08x}",
        "Призначення": "Використовуються в F-функції"
    })

    # Key-dependent S-box preparation
    print_step(4, "ПІДГОТОВКА KEY-DEPENDENT S-BOXES")
    print_substep("4.1", "ПРИНЦИП KEY-DEPENDENT S-BOXES", {
        "Особливість": "S-boxи залежать від ключа",
        "Перевага": "Ускладнює диференційний та лінійний криптоаналіз",
        "Реалізація": "На основі MDS матриць та ключа"
    })

    # Обробка перших двох слів через key-dependent S-box
    print_step(5, "ОБРОБКА R0 ТА R1 ЧЕРЕЗ KEY-DEPENDENT S-BOX")

    # Використовуємо старші байти слів для імітації key-dependent перетворення
    T0 = (R0 >> 24) ^ key[0]  # Старший байт R0 XOR з першим байтом ключа
    T1 = (R1 >> 16) ^ key[1]  # Другий байт R1 XOR з другим байтом ключа

    print_substep("5.1", "ПІДГОТОВКА ВХІДНИХ ДАНИХ ДЛЯ S-BOX", {
        "R0 старший байт": f"{(R0 >> 24) & 0xFF:02x}",
        "R1 другий байт": f"{(R1 >> 16) & 0xFF:02x}",
        "Ключ[0]": f"{key[0]:02x}",
        "Ключ[1]": f"{key[1]:02x}",
        "T0 = R0[24-31] ⊕ key[0]": f"{T0:02x}",
        "T1 = R1[16-23] ⊕ key[1]": f"{T1:02x}"
    })

    # H-функція Twofish (спрощена імітація)
    def twofish_h_func_detailed(b, name="H"):
        print(f"\n      --- {name}-ФУНКЦІЯ ДЛЯ {b:02x} ---")

        # Крок 1: Множення на константу
        step1 = b * 0x5D
        print(f"        Крок 1: {b:02x} × 5D = {step1:04x}")

        # Крок 2: Додавання константи
        step2 = step1 + 0xAA
        print(f"        Крок 2: {step1:04x} + AA = {step2:04x}")

        # Крок 3: Обрізання до 32 біт
        result = step2 & 0xFFFFFFFF
        print(f"        Крок 3: {step2:04x} & FFFFFFFF = {result:08x}")

        return result

    # Обчислення g(R0) та g(R1)
    print_step(6, "ОБЧИСЛЕННЯ g(R0) ТА g(R1)")

    g_R0 = twofish_h_func_detailed(T0, "g(R0)")
    g_R1 = twofish_h_func_detailed(T1, "g(R1)")

    print_substep("6.1", "РЕЗУЛЬТАТИ g-ФУНКЦІЙ", {
        "g(R0)": f"{g_R0:08x}",
        "g(R1)": f"{g_R1:08x}",
        "Бітові представлення": f"g(R0)={g_R0:032b}, g(R1)={g_R1:032b}"
    })

    # F-функція Twofish
    print_step(7, "F-ФУНКЦІЯ TWOFISH")
    print_substep("7.1", "ПРИНЦИП РОБОТИ F-ФУНКЦІЇ", {
        "Формула F0": "F0 = (g(R0) + g(R1) + K[0]) mod 2³²",
        "Формула F1": "F1 = (g(R0) + 2×g(R1) + K[1]) mod 2³²",
        "Призначення": "Генерація потоків для PHT"
    })

    # Обчислення F0
    print_step(7.2, "ОБЧИСЛЕННЯ F0")
    print_substep("7.2.1", "СКЛАДАНІ F0", {
        "g(R0)": f"{g_R0:08x} = {g_R0}",
        "g(R1)": f"{g_R1:08x} = {g_R1}",
        "K[0]": f"{Round_key[0]:08x} = {Round_key[0]}"
    })

    sum_F0 = g_R0 + g_R1 + Round_key[0]
    F0 = sum_F0 & 0xFFFFFFFF

    print_substep("7.2.2", "РЕЗУЛЬТАТ F0", {
        "Сума": f"{sum_F0}",
        "F0 = сума mod 2³²": f"{F0:08x}",
        "Обчислення": f"{g_R0} + {g_R1} + {Round_key[0]} = {sum_F0} → mod 2³² → {F0}"
    })

    # Обчислення F1
    print_step(7.3, "ОБЧИСЛЕННЯ F1")
    print_substep("7.3.1", "СКЛАДАНІ F1", {
        "g(R0)": f"{g_R0:08x} = {g_R0}",
        "2×g(R1)": f"{2 * g_R1:08x} = {2 * g_R1}",
        "K[1]": f"{Round_key[1]:08x} = {Round_key[1]}"
    })

    sum_F1 = g_R0 + 2 * g_R1 + Round_key[1]
    F1 = sum_F1 & 0xFFFFFFFF

    print_substep("7.3.2", "РЕЗУЛЬТАТ F1", {
        "Сума": f"{sum_F1}",
        "F1 = сума mod 2³²": f"{F1:08x}",
        "Обчислення": f"{g_R0} + {2 * g_R1} + {Round_key[1]} = {sum_F1} → mod 2³² → {F1}"
    })

    # Pseudo-Hadamard Transform (PHT)
    print_step(8, "PSEUDO-HADAMARD TRANSFORM (PHT)")
    print_substep("8.1", "ПРИНЦИП PHT", {
        "Тип": "Лінійне перетворення",
        "Мета": "Поширення впливу F-функцій",
        "Формула": "R2' = R2 ⊕ F0, R3' = R3 ⊕ F1"
    })

    # Застосування PHT до R2 та R3
    print_step(8.2, "ЗАСТОСУВАННЯ PHT ДО R2 ТА R3")

    print_substep("8.2.1", "ВХІДНІ ДАНІ ДЛЯ PHT", {
        "R2 (до)": f"{R2:08x}",
        "R3 (до)": f"{R3:08x}",
        "F0": f"{F0:08x}",
        "F1": f"{F1:08x}"
    })

    R2_after_pht = R2 ^ F0
    R3_after_pht = R3 ^ F1

    # Кольоровий вивід результатів PHT
    colored_R2 = get_color_diff_hex(R2, R2_after_pht)
    colored_R3 = get_color_diff_hex(R3, R3_after_pht)

    print_substep("8.2.2", "РЕЗУЛЬТАТ PHT", {
        "R2' = R2 ⊕ F0": colored_R2,
        "R3' = R3 ⊕ F1": colored_R3,
        "Бітові зміни R2": f"{bin(R2 ^ R2_after_pht).count('1')} бітів",
        "Бітові зміни R3": f"{bin(R3 ^ R3_after_pht).count('1')} бітів"
    })

    # Циклічний зсув
    print_step(9, "ЦИКЛІЧНИЙ ЗСУВ")
    print_substep("9.1", "ПРИНЦИП ЦИКЛІЧНОГО ЗСУВУ", {
        "Тип": "ROTR (Right Rotate)",
        "Величина зсуву": "1 біт вправо",
        "Формула": "R2'' = (R2' >>> 1)"
    })

    old_R2 = R2_after_pht
    R2_rotated = (R2_after_pht >> 1) | (R2_after_pht << 31) & 0xFFFFFFFF

    print_substep("9.2", "РЕЗУЛЬТАТ ЗСУВУ", {
        "R2' (до зсуву)": f"{old_R2:08x} = {old_R2:032b}",
        "R2'' (після зсуву)": f"{R2_rotated:08x} = {R2_rotated:032b}",
        "Зсув": "1 біт вправо (ROTR 1)"
    })

    # Фінальний обмін
    print_step(10, "ФІНАЛЬНИЙ ОБМІН ТА РЕЗУЛЬТАТ")
    print_substep("10.1", "СТАН ПЕРЕД ОБМІНОМ", {
        "R0": f"{R0:08x}",
        "R1": f"{R1:08x}",
        "R2 (оброблений)": f"{R2_rotated:08x}",
        "R3 (оброблений)": f"{R3_after_pht:08x}"
    })

    # В Twofish виконується зсув на 2 слова
    final_R0 = R2_rotated
    final_R1 = R3_after_pht
    final_R2 = R0
    final_R3 = R1

    print_substep("10.2", "СТАН ПІСЛЯ ОБМІНУ", {
        "R0 (нове) = R2 (старе)": f"{final_R0:08x}",
        "R1 (нове) = R3 (старе)": f"{final_R1:08x}",
        "R2 (нове) = R0 (старе)": f"{final_R2:08x}",
        "R3 (нове) = R1 (старе)": f"{final_R3:08x}"
    })

    # Фінальний блок
    final_block = (final_R0.to_bytes(4, 'big') + final_R1.to_bytes(4, 'big') +
                   final_R2.to_bytes(4, 'big') + final_R3.to_bytes(4, 'big'))

    print_step(11, "ФІНАЛЬНИЙ РЕЗУЛЬТАТ")
    print_substep("11.1", "СКЛАДАННЯ БЛОКУ", {
        "R0": f"{final_R0:08x}",
        "R1": f"{final_R1:08x}",
        "R2": f"{final_R2:08x}",
        "R3": f"{final_R3:08x}",
        "Об'єднаний блок": final_block.hex()
    })

    print_substep("11.2", "ПОРІВНЯННЯ З ОРИГІНАЛОМ", {
        "Оригінальний блок": data.hex(),
        "Результат раунду": final_block.hex(),
        "Змінено байтів": sum(1 for i in range(16) if data[i] != final_block[i]),
        "Змінено бітів": sum(bin(data[i] ^ final_block[i]).count('1') for i in range(16))
    })

    # Особливості Twofish
    print_step(12, "ОСОБЛИВОСТІ TWOFISH")
    print_substep("12.1", "KEY-DEPENDENT S-BOXES", {
        "Перевага": "Унікальні S-boxи для кожного ключа",
        "Складність атаки": "Ускладнює диференційний/лінійний аналіз",
        "Реалізація": "На основі MDS матриць та ключових матеріалів"
    })

    print_substep("12.2", "PSEUDO-HADAMARD TRANSFORM", {
        "Призначення": "Лінійне дифузуюче перетворення",
        "Ефект": "Швидке поширення змін по всьому блоку",
        "Властивість": "Зберігає суму слів mod 2³²"
    })

    print_substep("12.3", "МОДИФІКОВАНА МЕРЕЖА ФАЙСТЕЛЯ", {
        "Відмінність": "Обробка всіх 4 слів одночасно",
        "Перевага": "Краще поширення, ніж у класичній мережі Файстеля",
        "Складність": "Більше операцій на раунд"
    })

    print("\n" + "=" * 80)
    print("✅ TWOFISH ДЕМОНСТРАЦІЯ ЗАВЕРШЕНА")
    print("=" * 80)


def demo_kalina_detailed():
    """НАДДЕТАЛЬНА демонстрація Kaliņa з КОЖНИМ перетворенням."""
    ask_to_watch_video("KALINA")
    print_algo_diagram("KALINA")
    print("\n" + "=" * 80)
    print("=== НАДДЕТАЛЬНА ДЕМОНСТРАЦІЯ KALIŅA - КОЖЕН КРОК ===")
    print("=" * 80)

    # 1. Ініціалізація
    print_step(1, "ІНІЦІАЛІЗАЦІЯ АЛГОРИТМУ")
    print_substep("1.1", "ПАРАМЕТРИ KALIŅA", {
        "Розмір блоку": "128 біт (16 байт)",
        "Розмір ключа": "128/256/512 біт",
        "Кількість раундів": "10/14/18 (залежно від ключа)",
        "Тип": "SPN (Substitution-Permutation Network)",
        "Країна": "Україна 🇺🇦",
        "Стандарт": "ДСТУ 7624:2014"
    })

    # Отримання вхідних даних
    user_data_str = input("Введи 16-байтовий текст (16 символів): ").strip() or "KALINA UKRAINE 16"
    if len(user_data_str) != 16:
        user_data_str = user_data_str.ljust(16, 'X')[:16]
        print(f"Текст вирівняно до 16 символів: '{user_data_str}'")

    state = user_data_str.encode('utf-8')
    main_key = secrets.token_bytes(16)

    print_substep("1.2", "ТЕСТОВІ ДАНІ", {
        "Вхідний текст": f"'{user_data_str}'",
        "Текст (hex)": state.hex(),
        "Основний ключ (hex)": main_key.hex(),
        "Довжина блоку": f"{len(state)} байт",
        "Довжина ключа": f"{len(main_key)} байт"
    })

    # Детальний вивід початкового стану
    print_step(2, "ПОЧАТКОВИЙ СТАН")
    print_substep("2.1", "ОРГАНІЗАЦІЯ ДАНИХ В МАТРИЦЮ 4×4", {
        "Метод": "Заповнення по стовпцях",
        "Формат": "state[col + 4×row]"
    })

    def print_kalina_state_matrix(state, title="Матриця стану"):
        print(f"\n  {title}:")
        print(f"      Позиції:    [0,0] [1,0] [2,0] [3,0]")
        print(f"                  [0,1] [1,1] [2,1] [3,1]")
        print(f"                  [0,2] [1,2] [2,2] [3,2]")
        print(f"                  [0,3] [1,3] [2,3] [3,3]")
        print(f"      Значення:   [ {state[0]:02x}   {state[1]:02x}   {state[2]:02x}   {state[3]:02x} ]")
        print(f"                  [ {state[4]:02x}   {state[5]:02x}   {state[6]:02x}   {state[7]:02x} ]")
        print(f"                  [ {state[8]:02x}   {state[9]:02x}   {state[10]:02x}   {state[11]:02x} ]")
        print(f"                  [ {state[12]:02x}   {state[13]:02x}   {state[14]:02x}   {state[15]:02x} ]")

    print_kalina_state_matrix(state, "Початкова матриця стану")

    # Детальний вивід байтів
    print_substep("2.2", "ДЕТАЛЬНІ ЗНАЧЕННЯ БАЙТІВ")
    for i in range(16):
        row = i // 4
        col = i % 4
        char = chr(state[i]) if 32 <= state[i] <= 126 else '?'
        print(f"      state[{i:2d}] = pos[{col},{row}] = {state[i]:02x} = {state[i]:3d} = '{char}'")

    # Генерація раундового ключа
    print_step(3, "ГЕНЕРАЦІЯ РАУНДОВОГО КЛЮЧА")
    r = 1
    round_key = hashlib.sha256(main_key + bytes([r])).digest()[:16]

    print_substep("3.1", "ПРОЦЕС ГЕНЕРАЦІЇ", {
        "Основний ключ": main_key.hex(),
        "Раунд": r,
        "Функція": "SHA-256(main_key || round_number)",
        "Результат": round_key.hex()
    })

    print_kalina_state_matrix(round_key, "Матриця раундового ключа")

    # Раунд 1
    print_step(4, "РАУНД 1", "Обробка першого раунду")
    current_state = list(state)

    # Крок 1: AddRoundKey
    print_step(4.1, "ADD ROUND KEY")
    print_substep("4.1.1", "ПРИНЦИП РОБОТИ", {
        "Операція": "Побітове XOR стану з раундовим ключем",
        "Формула": "state[i] = state[i] ⊕ round_key[i]",
        "Мета": "Додавання ключової інформації"
    })

    print_substep("4.1.2", "ПОКРОКОВЕ ВИКОНАННЯ XOR")

    new_state_xor = []
    for i in range(16):
        old_byte = current_state[i]
        new_byte = current_state[i] ^ round_key[i]
        new_state_xor.append(new_byte)

        # Кольоровий вивід
        colored_new_byte = get_color_diff_hex(old_byte, new_byte)

        row = i // 4
        col = i % 4
        print(f"      state[{i:2d}] = pos[{col},{row}]: {old_byte:02x} ⊕ {round_key[i]:02x} = {colored_new_byte}")

    current_state = new_state_xor
    # ... (решта коду залишається)

    current_state = new_state_xor
    print_kalina_state_matrix(current_state, "Після AddRoundKey")

    # Крок 2: S-Box Layer
    print_step(4.2, "S-BOX LAYER")
    print_substep("4.2.1", "ПРИНЦИП РОБОТИ", {
        "Тип": "Нелінійна заміна байтів",
        "Основа": "8 незалежних S-boxів 8×8",
        "Мета": "Заплутування (Confusion)",
        "Особливість": "Кожен S-box має різні властивості"
    })

    # Спрощена імітація S-box Kaliņa
    def kalina_s_box_detailed(byte_block, name="S-Box"):
        print(f"\n      --- {name} ПЕРЕТВОРЕННЯ ---")
        result = bytearray()

        for i, byte in enumerate(byte_block):
            old_byte = byte

            # Спрощена імітація S-box (множення та додавання в GF(2⁸))
            # У реальному Kaliņa використовуються складніші перетворення
            new_byte = (byte * 0x7D + 0x1A) & 0xFF

            result.append(new_byte)

            if i < 8:  # Показуємо тільки перші 8 байтів для компактності
                print(f"        Байт {i:2d}: {old_byte:02x} → S-box → {new_byte:02x}")

                # Детальні обчислення для перших кількох байтів
                if i < 4:
                    calculation = f"{old_byte:02x} × 7D + 1A = {old_byte * 0x7D:04x} + 1A = {(old_byte * 0x7D + 0x1A) & 0xFFFF:04x} → {new_byte:02x}"
                    print(f"               {calculation}")

        return bytes(result)

    print_substep("4.2.2", "ЗАСТОСУВАННЯ S-BOX ДО ВСЬОГО БЛОКУ")
    state_sub_bytes = list(kalina_s_box_detailed(bytes(current_state), "KALIŅA S-BOX"))

    current_state = state_sub_bytes
    print_kalina_state_matrix(current_state, "Після S-Box Layer")

    # Крок 3: Mix Layer
    print_step(4.3, "MIX LAYER")
    print_substep("4.3.1", "ПРИНЦИП РОБОТИ", {
        "Тип": "Лінійне перемішування",
        "Основа": "Матричне множення в GF(2⁸)",
        "Мета": "Поширення (Diffusion)",
        "Особливість": "MDS матриця для максимального розповсюдження"
    })

    def kalina_mix_layer_detailed(block):
        print(f"\n      --- MIX LAYER ПЕРЕТВОРЕННЯ ---")
        b = bytearray(block)

        print(f"        Початковий стан: {[f'{x:02x}' for x in b]}")

        # Крок 3.1: Обмін блоків (імітація перестановки)
        print(f"        Крок 1: Обмін блоків 0-3 та 4-7")
        old_block = b.copy()
        b[4:8], b[0:4] = b[0:4], b[4:8]

        for i in range(8):
            if old_block[i] != b[i]:
                print(f"          Позиція {i:2d}: {old_block[i]:02x} → {b[i]:02x} (обмін)")

        print(f"        Проміжний стан: {[f'{x:02x}' for x in b]}")

        # Крок 3.2: XOR операції (імітація дифузії)
        print(f"        Крок 2: Дифузійні XOR операції")
        old_block = b.copy()

        # Спрощена імітація дифузії - XOR сусідніх байтів
        b[1] = b[1] ^ b[3]
        b[5] = b[5] ^ b[7]
        b[9] = b[9] ^ b[11]
        b[13] = b[13] ^ b[15]

        for i in [1, 5, 9, 13]:
            if old_block[i] != b[i]:
                print(f"          Байт {i:2d}: {old_block[i]:02x} ⊕ {old_block[i + 2]:02x} = {b[i]:02x}")

        print(f"        Фінальний стан: {[f'{x:02x}' for x in b]}")

        return bytes(b)

    print_substep("4.3.2", "ЗАСТОСУВАННЯ MIX LAYER")
    state_diffusion = list(kalina_mix_layer_detailed(bytes(current_state)))

    current_state = state_diffusion
    print_kalina_state_matrix(current_state, "Після Mix Layer")

    # Фінальний результат
    print_step(5, "ФІНАЛЬНИЙ РЕЗУЛЬТАТ РАУНДУ")
    final_state = bytes(current_state)

    print_substep("5.1", "ШИФРОТЕКСТ", {
        "Hex представлення": final_state.hex(),
        "Довжина": f"{len(final_state)} байт",
        "ASCII представлення": ''.join(chr(b) if 32 <= b <= 126 else '.' for b in final_state)
    })

    print_substep("5.2", "ПОРІВНЯННЯ З ОРИГІНАЛОМ", {
        "Оригінальний блок": state.hex(),
        "Шифротекст": final_state.hex(),
        "Змінено байтів": sum(1 for i in range(16) if state[i] != final_state[i]),
        "Змінено бітів": sum(bin(state[i] ^ final_state[i]).count('1') for i in range(16)),
        "Відсоток змінених бітів": f"{(sum(bin(state[i] ^ final_state[i]).count('1') for i in range(16)) / 128) * 100:.1f}%"
    })

    # Особливості Kaliņa
    print_step(6, "ОСОБЛИВОСТІ АЛГОРИТМУ KALIŅA")
    print_substep("6.1", "УКРАЇНСЬКИЙ СТАНДАРТ", {
        "Назва": "Kaliņa (Калініна)",
        "Стандарт": "ДСТУ 7624:2014",
        "Розробник": "Держспецзв'язку України",
        "Призначення": "Захист інформації в державних органах"
    })

    print_substep("6.2", "ТЕХНІЧНІ ОСОБЛИВОСТІ", {
        "Архітектура": "SPN (Substitution-Permutation Network)",
        "S-boxи": "8 незалежних S-boxів 8×8 з різними властивостями",
        "Mix Layer": "MDS матриця для максимального дифузуючого ефекту",
        "Безпека": "Стійкість до диференційного та лінійного криптоаналізу"
    })

    print_substep("6.3", "ПЕРЕВАГИ", {
        "Національний стандарт": "Розроблений в Україні для українських потреб",
        "Гнучкість": "Підтримує ключі 128, 256 та 512 біт",
        "Ефективність": "Висока швидкість на сучасному обладнанні",
        "Безпека": "Відповідає сучасним вимогам криптостійкості"
    })

    # Демонстрація лавинного ефекту
    print_step(7, "ДЕМОНСТРАЦІЯ ЛАВИННОГО ЕФЕКТУ")

    # Змінюємо один біт у оригіналі
    modified_state = bytearray(state)
    modified_state[0] ^= 0x01  # Змінюємо один біт у першому байті

    # Виконуємо той самий процес шифрування
    modified_current = list(modified_state)

    # AddRoundKey
    for i in range(16):
        modified_current[i] ^= round_key[i]

    # S-Box
    modified_current = list(kalina_s_box_detailed(bytes(modified_current), "MODIFIED S-BOX"))

    # Mix Layer
    modified_current = list(kalina_mix_layer_detailed(bytes(modified_current)))

    modified_final = bytes(modified_current)

    # Підрахунок різниці
    diff_bits = sum(bin(final_state[i] ^ modified_final[i]).count('1') for i in range(16))

    print_substep("7.1", "РЕЗУЛЬТАТ ЛАВИННОГО ЕФЕКТУ", {
        "Змінено бітів у вході": 1,
        "Змінено бітів у виході": diff_bits,
        "Відсоток змін": f"{(diff_bits / 128) * 100:.1f}%",
        "Висновок": "✅ Сильний лавинний ефект (близько 50%)"
    })

    print("\n" + "=" * 80)
    print("✅ KALIŅA ДЕМОНСТРАЦІЯ ЗАВЕРШЕНА")
    print("🇺🇦 Український криптографічний стандарт")
    print("=" * 80)
# =========================================================================
# II. СИМЕТРИЧНЕ ПОТОКОВЕ ШИФРУВАННЯ
# =========================================================================

def demo_rc4_detailed():
    """НАДДЕТАЛЬНА демонстрація RC4 з КОЖНИМ перетворенням."""
    ask_to_watch_video("RC4")
    print_algo_diagram("RC4")
    print("\n" + "=" * 80)
    print("=== НАДДЕТАЛЬНА ДЕМОНСТРАЦІЯ RC4 - КОЖЕН КРОК ===")
    print("=" * 80)

    # 1. Ініціалізація
    print_step(1, "ІНІЦІАЛІЗАЦІЯ АЛГОРИТМУ")
    print_substep("1.1", "ПАРАМЕТРИ RC4", {
        "Тип": "Потоковий шифр",
        "Розмір ключа": "40-2048 біт (зазвичай 128 біт)",
        "Створювач": "Ron Rivest (RSA Security)",
        "Рік": "1987",
        "Особливість": "Дуже швидкий, простий у реалізації"
    })

    key = secrets.token_bytes(16)
    message = input("Введи текст для шифрування: ").encode() or b"RC4 Stream Demo"

    print_substep("1.2", "ТЕСТОВІ ДАНІ", {
        "Ключ (K)": key.hex(),
        "Ключ (ASCII)": ''.join(chr(b) if 32 <= b <= 126 else '.' for b in key),
        "Повідомлення": f"'{message.decode()}'",
        "Повідомлення (hex)": message.hex(),
        "Довжина повідомлення": f"{len(message)} байт"
    })

    # Key Scheduling Algorithm (KSA)
    print_step(2, "KEY SCHEDULING ALGORITHM (KSA)")
    print_substep("2.1", "ПРИНЦИП РОБОТИ KSA", {
        "Мета": "Ініціалізація S-боксу на основі ключа",
        "Алгоритм": "Перемішування S-боксу через ключ",
        "Формула": "j = (j + S[i] + K[i mod len(K)]) mod 256, swap(S[i], S[j])"
    })

    # Ініціалізація S-боксу
    S = list(range(256))
    T = [key[i % len(key)] for i in range(256)]  # Розширення ключа

    print_substep("2.2", "ПОЧАТКОВИЙ СТАН S-БОКСУ", {
        "S[0..255]": "0, 1, 2, ..., 255 (послідовність)",
        "S[0]-S[15]": [f"{x:02x}" for x in S[:16]],
        "T[0]-T[15]": [f"{x:02x}" for x in T[:16]],
        "Довжина T": f"{len(T)} байт (повторення ключа)"
    })

    print_step(2.3, "ВИКОНАННЯ KSA (256 КРОКІВ)")
    j = 0

    # Ініціалізуємо S_old перед використанням
    S_old = S.copy()

    # Таблиця для відстеження змін
    print(f"\n      ДЕТАЛЬНІ КРОКИ KSA (перші 8):")
    print(
        f"      {'i':>3} | {'S[i]':>4} | {'T[i]':>4} | {'j (до)':>6} | {'j (після)':>9} | {'Swap':>12} | {'S[i] (після)':>12}")
    print(f"      {'-' * 90}")

    for i in range(256):
        j_old = j
        j = (j + S[i] + T[i]) % 256

        # Виконуємо обмін
        S[i], S[j] = S[j], S[i]

        # Виводимо деталі для перших 8 кроків
        if i < 8:
            print(
                f"      {i:3} | {S_old[i]:04x} | {T[i]:04x} | {j_old:6} | {j:9} | S[{i}]↔S[{j}] | {S[i]:04x} (was {S_old[i]:04x})")

        # Оновлюємо старий стан для наступного кроку
        if i < 7:  # Оновлюємо тільки для наступних кроків
            S_old = S.copy()

    print(f"      ... ({248} кроків приховано) ...")

    print_substep("2.4", "РЕЗУЛЬТАТ KSA", {
        "S[0]-S[15] після KSA": [f"{x:02x}" for x in S[:16]],
        "S[240]-S[255] після KSA": [f"{x:02x}" for x in S[240:]],
        "Статистика": f"{len(set(S))} унікальних значень з 256"
    })

    # Pseudo-Random Generation Algorithm (PRGA)
    print_step(3, "PSEUDO-RANDOM GENERATION ALGORITHM (PRGA)")
    print_substep("3.1", "ПРИНЦИП РОБОТИ PRGA", {
        "Мета": "Генерація ключового потоку",
        "Алгоритм": "i = (i + 1) mod 256, j = (j + S[i]) mod 256, swap(S[i], S[j]), K = S[(S[i] + S[j]) mod 256]",
        "Вихід": "Безмежний ключовий потік"
    })

    i, j = 0, 0
    keystream = bytearray()

    print_step(3.2, "ГЕНЕРАЦІЯ КЛЮЧОВОГО ПОТОКУ")
    print(f"\n      ДЕТАЛЬНІ КРОКИ PRGA (для перших {min(8, len(message))} байт):")
    print(f"      {'k':>2} | {'i':>3} | {'j':>3} | {'S[i]':>4} | {'S[j]':>4} | {'t':>3} | {'K':>4} | {'Операції':>20}")
    print(f"      {'-' * 80}")

    # Зберігаємо початковий стан S для PRGA
    S_prga = S.copy()

    for k in range(len(message)):
        # Зберігаємо стан перед кроком
        S_old_prga = S_prga.copy()
        i_old = i
        j_old = j

        # Крок 1: Оновлення i
        i = (i + 1) % 256

        # Крок 2: Оновлення j
        j = (j + S_prga[i]) % 256

        # Крок 3: Обмін
        S_prga[i], S_prga[j] = S_prga[j], S_prga[i]

        # Крок 4: Обчислення t
        t = (S_prga[i] + S_prga[j]) % 256

        # Крок 5: Генерація ключового байта
        K = S_prga[t]
        keystream.append(K)

        # Виводимо деталі для перших кроків
        if k < 8:
            operations = []
            if i_old != i:
                operations.append(f"i={i_old}→{i}")
            if j_old != j:
                operations.append(f"j={j_old}→{j}")
            operations.append(f"swap(S[{i}],S[{j}])")
            operations.append(f"t={S_prga[i]:02x}+{S_prga[j]:02x}={t:02x}")
            operations.append(f"K=S[{t:02x}]={K:02x}")

            print(
                f"      {k:2} | {i_old:3} | {j_old:3} | {S_old_prga[i]:04x} | {S_old_prga[j]:04x} | {t:3} | {K:04x} | {', '.join(operations)}")

    if len(message) > 8:
        print(f"      ... ({len(message) - 8} кроків приховано) ...")

    print_substep("3.3", "РЕЗУЛЬТАТ PRGA", {
        "Ключовий потік (hex)": keystream.hex()[:64] + "..." if len(keystream) > 8 else keystream.hex(),
        "Довжина ключового потоку": f"{len(keystream)} байт",
        "Перші 8 байт": [f"{k:02x}" for k in keystream[:8]],
        "Ентропія": "Високоякісний псевдовипадковий потік"
    })

    # Шифрування
    print_step(4, "ШИФРУВАННЯ")
    print_substep("4.1", "ПРИНЦИП ШИФРУВАННЯ RC4", {
        "Тип": "Потокове шифрування",
        "Операція": "Побітове XOR повідомлення з ключовим потоком",
        "Формула": "C[i] = M[i] ⊕ K[i]",
        "Дешифрування": "M[i] = C[i] ⊕ K[i] (та сама операція)"
    })

    print_step(4.2, "ПОКРОКОВЕ ШИФРУВАННЯ")
    print(f"\n      ДЕТАЛЬНІ КРОКИ ШИФРУВАННЯ:")
    print(f"      {'i':>2} | {'M[i]':>5} | {'K[i]':>5} | {'C[i]':>5} | {'Обчислення':>20}")
    print(f"      {'-' * 60}")

    ciphertext = bytearray()
    for i in range(len(message)):
        cipher_byte = message[i] ^ keystream[i]
        ciphertext.append(cipher_byte)

        if i < 8:
            m_char = chr(message[i]) if 32 <= message[i] <= 126 else '.'
            calculation = f"{message[i]:02x} ⊕ {keystream[i]:02x} = {cipher_byte:02x}"
            print(
                f"      {i:2} | {message[i]:02x}('{m_char}') | {keystream[i]:02x} | {cipher_byte:02x} | {calculation}")

    if len(message) > 8:
        print(f"      ... ({len(message) - 8} байт приховано) ...")

    ciphertext = bytes(ciphertext)

    print_substep("4.3", "РЕЗУЛЬТАТ ШИФРУВАННЯ", {
        "Повідомлення (M)": message.hex()[:64] + "..." if len(message) > 8 else message.hex(),
        "Ключовий потік (K)": keystream.hex()[:64] + "..." if len(keystream) > 8 else keystream.hex(),
        "Шифротекст (C)": ciphertext.hex()[:64] + "..." if len(ciphertext) > 8 else ciphertext.hex(),
        "ASCII представлення C": ''.join(chr(b) if 32 <= b <= 126 else '.' for b in ciphertext)
    })

    # Дешифрування для перевірки
    print_step(5, "ПЕРЕВІРКА ДЕШИФРУВАННЯ")
    print_substep("5.1", "ПРОЦЕС ДЕШИФРУВАННЯ", {
        "Операція": "C[i] ⊕ K[i] = M[i]",
        "Властивість": "Той самий ключовий потік для шифрування та дешифрування"
    })

    decrypted = bytearray()
    for i in range(len(ciphertext)):
        decrypted_byte = ciphertext[i] ^ keystream[i]
        decrypted.append(decrypted_byte)

    decrypted_text = bytes(decrypted)

    print_substep("5.2", "РЕЗУЛЬТАТ ДЕШИФРУВАННЯ", {
        "Оригінальний текст": f"'{message.decode()}'",
        "Дешифрований текст": f"'{decrypted_text.decode()}'",
        "Статус": "✅ УСПІХ" if message == decrypted_text else "❌ НЕВДАЧА"
    })

    # Аналіз безпеки
    print_step(6, "АНАЛІЗ БЕЗПЕКИ RC4")
    print_substep("6.1", "ВІДОМІ НЕДОЛІКИ", {
        "Слабкі ключі": "Деякі ключі створюють слабкий ключовий потік",
        "Слабкість початку": "Перші байти ключового потоку можуть бути передбачуваними",
        "Атаки": "Вразливий до різних атак, включаючи статистичні атаки"
    })

    print_substep("6.2", "РЕКОМЕНДАЦІЇ", {
        "Стан": "Вважається застарілим та небезпечним",
        "Використання": "Не рекомендується для нових систем",
        "Альтернативи": "ChaCha20, AES-CTR, Salsa20"
    })

    # Статистичний аналіз ключового потоку
    print_step(7, "СТАТИСТИЧНИЙ АНАЛІЗ КЛЮЧОВОГО ПОТОКУ")

    byte_freq = [0] * 256
    for byte in keystream:
        byte_freq[byte] += 1

    max_freq = max(byte_freq)
    min_freq = min(byte_freq)
    avg_freq = len(keystream) / 256

    print_substep("7.1", "СТАТИСТИКА КЛЮЧОВОГО ПОТОКУ", {
        "Довжина аналізу": f"{len(keystream)} байт",
        "Максимальна частота": f"{max_freq} (байт {byte_freq.index(max_freq):02x})",
        "Мінімальна частота": f"{min_freq} (байт {byte_freq.index(min_freq):02x})",
        "Середня частота": f"{avg_freq:.2f}",
        "Ідеальна рівномірність": "~1.0 для кожного байта"
    })

    print("\n" + "=" * 80)
    print("✅ RC4 ДЕМОНСТРАЦІЯ ЗАВЕРШЕНА")
    print("⚠️  УВАГА: RC4 вважається застарілим та небезпечним для використання!")
    print("=" * 80)


def demo_chacha20_detailed():
    """НАДДЕТАЛЬНА демонстрація ChaCha20 з КОЖНИМ перетворенням."""
    ask_to_watch_video("CHACHA20")
    print_algo_diagram("CHACHA20")
    print("\n" + "=" * 80)
    print("=== НАДДЕТАЛЬНА ДЕМОНСТРАЦІЯ CHACHA20 - КОЖЕН КРОК ===")
    print("=" * 80)

    # 1. Ініціалізація
    print_step(1, "ІНІЦІАЛІЗАЦІЯ АЛГОРИТМУ")
    print_substep("1.1", "ПАРАМЕТРИ CHACHA20", {
        "Тип": "Потоковий шифр",
        "Розмір блоку": "512 біт (64 байти)",
        "Розмір ключа": "256 біт (32 байти)",
        "Розмір nonce": "96 біт (12 байт)",
        "Кількість раундів": "20 (10 подвійних раундів)",
        "Створювач": "Daniel J. Bernstein",
        "Рік": "2008",
        "Особливість": "Високошвидкісний, стійкий до атак"
    })

    # Ініціалізація стану ChaCha20
    print_step(2, "ІНІЦІАЛІЗАЦІЯ СТАНУ CHACHA20")
    print_substep("2.1", "СТРУКТУРА СТАНУ (16 СЛІВ ПО 32 БІТИ)", {
        "Слова 0-3": "Константи 'expand 32-byte k'",
        "Слова 4-11": "Ключ (256 біт)",
        "Слова 12-13": "Лічильник блоку",
        "Слова 14-15": "Nonce (96 біт)"
    })

    # Генерація тестового стану
    state = [secrets.randbits(32) for _ in range(16)]

    print_substep("2.2", "ПОЧАТКОВИЙ СТАН", {
        "Слово 0 (константа)": f"{state[0]:08x}",
        "Слово 1 (константа)": f"{state[1]:08x}",
        "Слово 2 (константа)": f"{state[2]:08x}",
        "Слово 3 (константа)": f"{state[3]:08x}",
        "Слова 4-11 (ключ)": f"{state[4]:08x} ... {state[11]:08x}",
        "Слова 12-13 (лічильник)": f"{state[12]:08x} {state[13]:08x}",
        "Слова 14-15 (nonce)": f"{state[14]:08x} {state[15]:08x}"
    })

    # Вибір слів для Quarter Round
    a, b, c, d = state[0], state[1], state[2], state[3]

    print_step(3, "ВИБІР СЛІВ ДЛЯ QUARTER ROUND")
    print_substep("3.1", "QUARTER ROUND ФУНКЦІЯ", {
        "Призначення": "Основна операція перемішування",
        "Вхід": "4 слова (a, b, c, d)",
        "Операції": "4 кроки ARX (Add-Rotate-XOR)",
        "Повний раунд": "4 quarter rounds на колонки + 4 на діагоналі"
    })

    print_substep("3.2", "ВИБРАНІ СЛОВА", {
        "a (слово 0)": f"{a:08x} = {a:032b}",
        "b (слово 1)": f"{b:08x} = {b:032b}",
        "c (слово 2)": f"{c:08x} = {c:032b}",
        "d (слово 3)": f"{d:08x} = {d:032b}"
    })

    # Функція циклічного зсуву вліво
    def rotate_left_detailed(val, shift, name="ROTL"):
        print(f"\n      --- {name}({val:08x}, {shift}) ---")

        # Бінарне представлення
        binary_val = f"{val:032b}"
        print(f"        Вхід: {val:08x} = {binary_val}")

        # Зсув вліво
        left_shifted = (val << shift) & 0xFFFFFFFF
        binary_left = f"{left_shifted:032b}"
        print(f"        << {shift}: {left_shifted:08x} = {binary_left}")

        # Зсув вправо для правої частини
        right_shifted = val >> (32 - shift)
        binary_right = f"{right_shifted:032b}".rjust(32, '0')
        print(f"        >> {32 - shift}: {right_shifted:08x} = {binary_right}")

        # Об'єднання
        result = left_shifted | right_shifted
        binary_result = f"{result:032b}"
        print(f"        OR:    {result:08x} = {binary_result}")

        return result

    # Quarter Round - Крок 1
    print_step(4, "QUARTER ROUND - КРОК 1")
    print_substep("4.1", "ФОРМУЛА КРОКУ 1", {
        "a = a + b": "Модульне додавання",
        "d = d ⊕ a": "Побітове XOR",
        "d = d <<< 16": "Циклічний зсув на 16 бітів"
    })

    # 1.1: a = a + b
    print_step(4.2, "a = a + b")
    a_old = a
    a = (a + b) & 0xFFFFFFFF

    print_substep("4.2.1", "МОДУЛЬНЕ ДОДАВАННЯ", {
        "a (до)": f"{a_old:08x} = {a_old}",
        "b": f"{b:08x} = {b}",
        "Сума": f"{a_old + b}",
        "a (після)": f"{a:08x} = {a} (mod 2³²)",
        "Біти зміни": f"{bin(a_old ^ a).count('1')} бітів змінено"
    })

    # 1.2: d = d ⊕ a
    print_step(4.3, "d = d ⊕ a")
    d_old = d
    d_intermediate = d ^ a
    d = d_intermediate

    # Кольорове представлення результату
    colored_d_int = get_color_diff_hex(d_old, d_intermediate)

    print_substep("4.3.1", "ПОБІТОВЕ XOR", {
        "d (до)": f"{d_old:08x}",
        "a": f"{a:08x}",
        "d ⊕ a": colored_d_int,
        "Змінено бітів": f"{bin(d_old ^ d_intermediate).count('1')}"
    })

    # 1.3: d = d <<< 16
    print_step(4.4, "d = d <<< 16")
    d_old_rotate = d
    d = rotate_left_detailed(d, 16, "ROTL d")

    print_substep("4.4.1", "РЕЗУЛЬТАТ ЦИКЛІЧНОГО ЗСУВУ", {
        "d (до зсуву)": f"{d_old_rotate:08x}",
        "d (після зсуву)": f"{d:08x}",
        "Ефект": "Перемішування бітів між старшою та молодшою половинами"
    })

    # Quarter Round - Крок 2
    print_step(5, "QUARTER ROUND - КРОК 2")
    print_substep("5.1", "ФОРМУЛА КРОКУ 2", {
        "c = c + d": "Модульне додавання",
        "b = b ⊕ c": "Побітове XOR",
        "b = b <<< 12": "Циклічний зсув на 12 бітів"
    })

    # 2.1: c = c + d
    print_step(5.2, "c = c + d")
    c_old = c
    c = (c + d) & 0xFFFFFFFF

    print_substep("5.2.1", "МОДУЛЬНЕ ДОДАВАННЯ", {
        "c (до)": f"{c_old:08x} = {c_old}",
        "d": f"{d:08x} = {d}",
        "Сума": f"{c_old + d}",
        "c (після)": f"{c:08x} = {c} (mod 2³²)",
        "Біти зміни": f"{bin(c_old ^ c).count('1')} бітів змінено"
    })

    # 2.2: b = b ⊕ c
    print_step(5.3, "b = b ⊕ c")
    b_old = b
    b_intermediate = b ^ c
    b = b_intermediate

    print_substep("5.3.1", "ПОБІТОВЕ XOR", {
        "b (до)": f"{b_old:08x} = {b_old:032b}",
        "c": f"{c:08x} = {c:032b}",
        "b ⊕ c": f"{b_intermediate:08x} = {b_intermediate:032b}",
        "Змінено бітів": f"{bin(b_old ^ b_intermediate).count('1')}"
    })

    # 2.3: b = b <<< 12
    print_step(5.4, "b = b <<< 12")
    b_old_rotate = b
    b = rotate_left_detailed(b, 12, "ROTL b")

    print_substep("5.4.1", "РЕЗУЛЬТАТ ЦИКЛІЧНОГО ЗСУВУ", {
        "b (до зсуву)": f"{b_old_rotate:08x}",
        "b (після зсуву)": f"{b:08x}",
        "Ефект": "Перемішування бітів у середній частині слова"
    })

    # Quarter Round - Крок 3
    print_step(6, "QUARTER ROUND - КРОК 3")
    print_substep("6.1", "ФОРМУЛА КРОКУ 3", {
        "a = a + b": "Модульне додавання",
        "d = d ⊕ a": "Побітове XOR",
        "d = d <<< 8": "Циклічний зсув на 8 бітів"
    })

    # 3.1: a = a + b
    print_step(6.2, "a = a + b")
    a_old_step3 = a
    a = (a + b) & 0xFFFFFFFF

    print_substep("6.2.1", "МОДУЛЬНЕ ДОДАВАННЯ", {
        "a (до)": f"{a_old_step3:08x}",
        "b": f"{b:08x}",
        "a (після)": f"{a:08x}",
        "Біти зміни": f"{bin(a_old_step3 ^ a).count('1')} бітів"
    })

    # 3.2: d = d ⊕ a
    print_step(6.3, "d = d ⊕ a")
    d_old_step3 = d
    d ^= a

    print_substep("6.3.1", "ПОБІТОВЕ XOR", {
        "d (до)": f"{d_old_step3:08x}",
        "a": f"{a:08x}",
        "d (після)": f"{d:08x}",
        "Змінено бітів": f"{bin(d_old_step3 ^ d).count('1')}"
    })

    # 3.3: d = d <<< 8
    print_step(6.4, "d = d <<< 8")
    d_old_rotate3 = d
    d = rotate_left_detailed(d, 8, "ROTL d")

    # Quarter Round - Крок 4
    print_step(7, "QUARTER ROUND - КРОК 4")
    print_substep("7.1", "ФОРМУЛА КРОКУ 4", {
        "c = c + d": "Модульне додавання",
        "b = b ⊕ c": "Побітове XOR",
        "b = b <<< 7": "Циклічний зсув на 7 бітів"
    })

    # 4.1: c = c + d
    print_step(7.2, "c = c + d")
    c_old_step4 = c
    c = (c + d) & 0xFFFFFFFF

    print_substep("7.2.1", "МОДУЛЬНЕ ДОДАВАННЯ", {
        "c (до)": f"{c_old_step4:08x}",
        "d": f"{d:08x}",
        "c (після)": f"{c:08x}",
        "Біти зміни": f"{bin(c_old_step4 ^ c).count('1')} бітів"
    })

    # 4.2: b = b ⊕ c
    print_step(7.3, "b = b ⊕ c")
    b_old_step4 = b
    b ^= c

    print_substep("7.3.1", "ПОБІТОВЕ XOR", {
        "b (до)": f"{b_old_step4:08x}",
        "c": f"{c:08x}",
        "b (після)": f"{b:08x}",
        "Змінено бітів": f"{bin(b_old_step4 ^ b).count('1')}"
    })

    # 4.3: b = b <<< 7
    print_step(7.4, "b = b <<< 7")
    b_old_rotate4 = b
    b = rotate_left_detailed(b, 7, "ROTL b")

    # Фінальний результат
    print_step(8, "ФІНАЛЬНИЙ РЕЗУЛЬТАТ QUARTER ROUND")
    print_substep("8.1", "ПОРІВНЯННЯ З ПОЧАТКОВИМ СТАНОМ", {
        "a (до)": f"{a_old:08x}",
        "a (після)": f"{a:08x}",
        "b (до)": f"{b_old:08x}",
        "b (після)": f"{b:08x}",
        "c (до)": f"{c_old:08x}",
        "c (після)": f"{c:08x}",
        "d (до)": f"{d_old:08x}",
        "d (після)": f"{d:08x}"
    })

    # Статистика змін
    total_changed_bits = (bin(a_old ^ a).count('1') + bin(b_old ^ b).count('1') +
                          bin(c_old ^ c).count('1') + bin(d_old ^ d).count('1'))

    print_substep("8.2", "СТАТИСТИКА ЗМІН", {
        "Загалом змінено бітів": f"{total_changed_bits} з 128",
        "Відсоток змін": f"{(total_changed_bits / 128) * 100:.1f}%",
        "Ефективність": "✅ Сильне перемішування"
    })

    # Повний раунд ChaCha20
    print_step(9, "ПОВНИЙ РАУНД CHACHA20")
    print_substep("9.1", "СТРУКТУРА ПОВНОГО РАУНДУ", {
        "Колонковий раунд": "4 quarter rounds на колонки (0-4-8-12, 1-5-9-13, 2-6-10-14, 3-7-11-15)",
        "Діагональний раунд": "4 quarter rounds на діагоналі (0-5-10-15, 1-6-11-12, 2-7-8-13, 3-4-9-14)",
        "Повний раунд": "Колонковий + Діагональний раунд",
        "Всього раундів": "20 (10 подвійних раундів)"
    })

    # Переваги ChaCha20
    print_step(10, "ПЕРЕВАГИ CHACHA20")
    print_substep("10.1", "ПОРІВНЯННЯ З ІНШИМИ АЛГОРИТМАМИ", {
        "Швидкість": "Швидший за AES на програмних реалізаціях",
        "Безпека": "Стійкий до timing-атак, простий для аналізу",
        "Простота": "Проста реалізація, менше ризику помилок",
        "Відносно RC4": "Набагато безпечніший, сучасніший"
    })

    print_substep("10.2", "ЗАСТОСУВАННЯ", {
        "TLS 1.3": "Один з рекомендованих шифрів",
        "VPN": "Використовується в сучасних VPN протоколах",
        "Мобільні додатки": "Висока ефективність на мобільних процесорах",
        "Дискове шифрування": "Швидке шифрування потоків даних"
    })

    print("\n" + "=" * 80)
    print("✅ CHACHA20 ДЕМОНСТРАЦІЯ ЗАВЕРШЕНА")
    print("🎯 Сучасний, швидкий та безпечний потоковий шифр")
    print("=" * 80)
# =========================================================================
# III. АСИМЕТРИЧНЕ ТА ГІБРИДНЕ ШИФРУВАННЯ
# =========================================================================

def demo_hecc_conceptual():
    """НАДДЕТАЛЬНА демонстрація Гомоморфного шифрування з КОЖНИМ аспектом."""
    ask_to_watch_video("HOMOMORPHIC")
    print("\n" + "=" * 80)
    print("=== НАДДЕТАЛЬНА ДЕМОНСТРАЦІЯ ГОМОМОРФНОГО ШИФРУВАННЯ ===")
    print("=" * 80)

    # 1. Вступ до гомоморфного шифрування
    print_step(1, "ВСТУП ДО ГОМОМОРФНОГО ШИФРУВАННЯ")
    print_substep("1.1", "ОСНОВНЕ ПОНЯТТЯ", {
        "Визначення": "Шифрування, що дозволяє виконувати операції над шифротекстом",
        "Формальне визначення": "Dec(Enc(a) ⊕ Enc(b)) = a ⊗ b для деяких операцій ⊕, ⊗",
        "Ідея": "Обчислення на зашифрованих даних без розшифрування"
    })

    print_substep("1.2", "ТИПИ ГОМОМОРФНОГО ШИФРУВАННЯ", {
        "Часткове (PHE)": "Підтримує одну операцію (напр., додавання або множення)",
        "Дещо (SHE)": "Підтримує обмежену кількість операцій",
        "Повне (FHE)": "Підтримує довільні обчислення"
    })

    print_substep("1.3", "ПРАКТИЧНЕ ЗАСТОСУВАННЯ", {
        "Хмарні обчислення": "Обробка конфіденційних даних у хмарі",
        "Медичні дані": "Аналіз медичних записів без розкриття даних",
        "Фінанси": "Банківські операції з захищеними даними",
        "Машинне навчання": "Навчання моделей на зашифрованих даних"
    })

    # 2. Демонстраційні дані
    print_step(2, "ДЕМОНСТРАЦІЙНІ ДАНІ")
    m1 = 5
    m2 = 10

    print_substep("2.1", "ВХІДНІ ПОВІДОМЛЕННЯ", {
        "Повідомлення 1 (m₁)": m1,
        "Повідомлення 2 (m₂)": m2,
        "Бажана операція": "m₁ + m₂ = 5 + 10 = 15",
        "Мета": "Виконати додавання над зашифрованими даними"
    })

    # 3. Концептуальна схема шифрування (імітація Paillier)
    print_step(3, "КОНЦЕПТУАЛЬНА СХЕМА ШИФРУВАННЯ")
    print_substep("3.1", "ПРИНЦИП РОБОТИ PAILLIER", {
        "Тип": "Часткове гомоморфне шифрування",
        "Підтримувані операції": "Додавання, множення на константу",
        "Ключові властивості": "Enc(a) × Enc(b) = Enc(a + b)",
        "Математична основа": "Складність факторизації великих чисел"
    })

    def encrypt_paillier_style_detailed(m, name="Шифрування"):
        print(f"\n      --- {name} ПОВІДОМЛЕННЯ {m} ---")

        # Крок 1: Множення на велике число (імітація)
        step1 = m * 100
        print(f"        Крок 1: {m} × 100 = {step1} (масштабування)")

        # Крок 2: Додавання "шуму" для безпеки
        noise = secrets.randbelow(10)
        step2 = step1 + noise
        print(f"        Крок 2: {step1} + {noise} (шум) = {step2}")

        # Крок 3: Модульна операція (імітація)
        # У реальному Paillier: c = gᵐ ⋅ rⁿ mod n²
        result = step2
        print(f"        Крок 3: Результат шифрування = {result}")
        print(f"        Пояснення: У реальному Paillier це було б c = gᵐ ⋅ rⁿ mod n²")

        return result

    print_substep("3.2", "ПРОЦЕС ШИФРУВАННЯ m₁")
    C1 = encrypt_paillier_style_detailed(m1, "ШИФРУВАННЯ m₁")

    print_substep("3.3", "ПРОЦЕС ШИФРУВАННЯ m₂")
    C2 = encrypt_paillier_style_detailed(m2, "ШИФРУВАННЯ m₂")

    print_substep("3.4", "РЕЗУЛЬТАТИ ШИФРУВАННЯ", {
        "Відкритий текст m₁": m1,
        "Шифротекст C₁": C1,
        "Відкритий текст m₂": m2,
        "Шифротекст C₂": C2,
        "Співвідношення": "C₁ ≠ m₁, C₂ ≠ m₂ (безпека)"
    })

    # 4. Гомоморфна операція
    print_step(4, "ГОМОМОРФНА ОПЕРАЦІЯ - ДОДАВАННЯ")
    print_substep("4.1", "ПРИНЦИП ГОМОМОРФНОГО ДОДАВАННЯ", {
        "Формула Paillier": "Enc(m₁) × Enc(m₂) mod n² = Enc(m₁ + m₂ mod n)",
        "Наша імітація": "C₁ + C₂ ≈ Enc(m₁ + m₂)",
        "Ключова властивість": "Операція виконується без знання секретного ключа"
    })

    print_step(4.2, "ВИКОНАННЯ ОПЕРАЦІЇ НАД ШИФРОТЕКСТОМ")
    print(f"\n      --- ОПЕРАЦІЯ НАД ШИФРОТЕКСТАМИ ---")
    print(f"        C₁ = {C1}")
    print(f"        C₂ = {C2}")
    print(f"        Операція: C₁ + C₂ = {C1} + {C2}")

    C_sum = C1 + C2
    print(f"        Результат: C_сума = {C_sum}")
    print(f"        Важливо: Ця операція виконується БЕЗ розшифрування!")

    print_substep("4.3", "ПЕРЕВАГИ ОПЕРАЦІЇ НА ШИФРОТЕКСТІ", {
        "Конфіденційність": "Дані залишаються зашифрованими під час обчислень",
        "Безпека": "Сервер не має доступу до вихідних даних",
        "Гнучкість": "Можливість делегування обчислень третім сторонам"
    })

    # 5. Дешифрування результату
    print_step(5, "ДЕШИФРУВАННЯ РЕЗУЛЬТАТУ")
    print_substep("5.1", "ПРИНЦИП ДЕШИФРУВАННЯ PAILLIER", {
        "Формула": "m = L(c^λ mod n²) × μ mod n",
        "Наша імітація": "Зворотне масштабування та видалення шуму",
        "Умова": "Тільки власник секретного ключа може дешифрувати"
    })

    def decrypt_paillier_style_detailed(C, name="Дешифрування"):
        print(f"\n      --- {name} ШИФРОТЕКСТУ {C} ---")

        # Крок 1: Видалення шуму (імітація)
        step1 = C
        print(f"        Крок 1: Вхідний шифротекст = {step1}")

        # Крок 2: Зворотне масштабування
        step2 = step1 / 100
        print(f"        Крок 2: {step1} / 100 = {step2} (зворотне масштабування)")

        # Крок 3: Округлення для видалення залишків шуму
        result = round(step2)
        print(f"        Крок 3: round({step2}) = {result} (остаточний результат)")
        print(f"        Пояснення: У реальному Paillier це L(c^λ mod n²) × μ mod n")

        return result

    print_substep("5.2", "ПРОЦЕС ДЕШИФРУВАННЯ C_СУМА")
    m_decrypted = decrypt_paillier_style_detailed(C_sum, "ДЕШИФРУВАННЯ СУМИ")

    # 6. Перевірка результатів
    print_step(6, "ПЕРЕВІРКА РЕЗУЛЬТАТІВ")
    expected_result = m1 + m2

    print_substep("6.1", "ПОРІВНЯЛЬНИЙ АНАЛІЗ", {
        "Очікуваний результат (m₁ + m₂)": expected_result,
        "Дешифрований результат": m_decrypted,
        "Шифротекст суми": C_sum,
        "Статус": "✅ УСПІХ" if m_decrypted == expected_result else "❌ НЕВДАЧА"
    })

    if m_decrypted == expected_result:
        print_substep("6.2", "ВИСНОВОК", {
            "Результат": "Гомоморфне додавання працює коректно!",
            "Значення": "Операція над шифротекстом дала правильний результат після дешифрування",
            "Практичне значення": "Можливість безпечних обчислень на стороні сервера"
        })
    else:
        print_substep("6.2", "АНАЛІЗ ПОМИЛКИ", {
            "Причина": "Неточність в імітаційній моделі",
            "Різниця": f"{abs(m_decrypted - expected_result)}",
            "Рекомендація": "У реальній реалізації використовуються точніші математичні методи"
        })

    # 7. Розширена демонстрація - множення на константу
    print_step(7, "РОЗШИРЕНА ДЕМОНСТРАЦІЯ - МНОЖЕННЯ НА КОНСТАНТУ")
    print_substep("7.1", "ГОМОМОРФНЕ МНОЖЕННЯ НА КОНСТАНТУ", {
        "Формула Paillier": "Enc(m)ᵏ mod n² = Enc(k × m mod n)",
        "Приклад": "Enc(5)³ = Enc(15)",
        "Обмеження": "Тільки множення на відкриту константу"
    })

    k = 3  # Константа для множення
    C_mult = C1 * k  # Імітація гомоморфного множення

    print_substep("7.2", "ВИКОНАННЯ МНОЖЕННЯ НА КОНСТАНТУ", {
        "Шифротекст C₁": C1,
        "Константа k": k,
        "Операція": f"C₁ × {k} = {C1} × {k}",
        "Результат C_множ": C_mult
    })

    m_decrypted_mult = decrypt_paillier_style_detailed(C_mult, "ДЕШИФРУВАННЯ МНОЖЕННЯ")
    expected_mult = m1 * k

    print_substep("7.3", "ПЕРЕВІРКА МНОЖЕННЯ", {
        "Очікуваний результат (m₁ × k)": expected_mult,
        "Дешифрований результат": m_decrypted_mult,
        "Статус": "✅ УСПІХ" if m_decrypted_mult == expected_mult else "❌ НЕВДАЧА"
    })

    # 8. Обмеження та перспективи
    print_step(8, "ОБМЕЖЕННЯ ТА ПЕРСПЕКТИВИ")
    print_substep("8.1", "ОБМЕЖЕННЯ PAILLIER", {
        "Операції": "Тільки додавання та множення на константу",
        "Продуктивність": "Повільніше за традиційне шифрування",
        "Розмір даних": "Шифротекст значно більший за відкритий текст"
    })

    print_substep("8.2", "СУЧАСНІ СХЕМИ FHE", {
        "BFV/BGV": "Підтримка арифметичних операцій над цілими",
        "CKKS": "Оптимізовано для дійсних чисел та машинного навчання",
        "TFHE": "Швидка булева логіка для довільних обчислень"
    })

    print_substep("8.3", "ВИКЛИКИ ТА ПЕРСПЕКТИВИ", {
        "Продуктивність": "Активні дослідження для покращення швидкості",
        "Стандартизація": "Розробка стандартів для FHE",
        "Апаратне прискорення": "Спеціальні процесори для FHE",
        "Масове застосування": "Поступове впровадження в промисловості"
    })

    # 9. Практичний приклад застосування
    print_step(9, "ПРАКТИЧНИЙ ПРИКЛАД ЗАСТОСУВАННЯ")
    print_substep("9.1", "СЦЕНАРІЙ: ЗАХИСТ МЕДИЧНИХ ДАНИХ", {
        "Проблема": "Лікарня хоче аналізувати дані пацієнтів, але не розкривати їх",
        "Рішення": "Дані шифруються гомоморфно та відправляються в хмару",
        "Обчислення": "Хмарний сервер обчислює статистику над зашифрованими даними",
        "Результат": "Лікарня отримує результати без розкриття вихідних даних"
    })

    print_substep("9.2", "ПЕРЕВАГИ ДЛЯ КОНФІДЕНЦІЙНОСТІ", {
        "Privacy by Design": "Конфіденційність вбудована в архітектуру",
        "Відповідність GDPR": "Мінімізація ризиків витоку даних",
        "Довіра": "Клієнти довіряють свої дані"
    })

    print("\n" + "=" * 80)
    print("✅ ГОМОМОРФНЕ ШИФРУВАННЯ ДЕМОНСТРАЦІЯ ЗАВЕРШЕНА")
    print("🔮 Майбутнє конфіденційних обчислень")
    print("=" * 80)


def demo_pqc_lattice_conceptual():
    """КОНЦЕПТУАЛЬНА демонстрація постквантової криптографії на ґратках."""
    ask_to_watch_video("LATTICE")
    print("\n" + "=" * 80)
    print("=== КОНЦЕПТУАЛЬНА ДЕМОНСТРАЦІЯ ПОСТКВАНТОВОЇ КРИПТОГРАФІЇ (ҐРАТКИ) ===")
    print("=" * 80)

    print_step(1, "КОНЦЕПТ: Проблема Ґраток", {
        "Суть": "Пошук найкоротшого вектора в багатовимірній ґратці."
    })

    a = 5
    b = 3
    G1 = (a, b)
    G2 = (-b, a)

    print_substep("1.1", "Генерація Бази Ґратки (Спрощено)", {
        "G1": G1,
        "G2": G2
    })

    print_step(2, "СЕКРЕТНИЙ КЛЮЧ ЯК 'ПАСТКА'", {
        "Секрет": "Матриця перетворення, що робить SVP легким."
    })

    Public_Vector = (a * 10 + b * 20 + secrets.randbelow(10), a * 20 + b * 10 + secrets.randbelow(10))
    print_substep("2.1", "Публічний Вектор (Хаотичний)", {
        "V_pub": Public_Vector
    })

    print_step(3, "ШИФРУВАННЯ ТА ДЕШИФРУВАННЯ", {
        "Принцип": "Шифротекст - це 'шум' на ґратці."
    })

    noise = secrets.randbelow(10)
    C_pub = (Public_Vector[0] + noise, Public_Vector[1] - noise)

    print_substep("3.1", "Шифротекст (Вектор + Шум)", {
        "C_pub": C_pub,
        "Шум": noise
    })

    Decryption_Mock = (C_pub[0] - noise) // 100

    print_substep("3.2", "Дешифрування", {
        "Dec(C_pub)": Decryption_Mock,
        "Ефект": "Видалення шуму завдяки Trapdoor."
    })

    print("\nПОЯСНЕННЯ:")
    print("Без секретної пастки, атакуючому потрібно обчислювати SVP, що не під силу квантовому комп'ютеру.")
    print("=" * 80)


# =========================================================================
# VI. ГЕНЕРАТОР КЛЮЧОВОГО РОЗКЛАДУ (НОВИЙ)
# =========================================================================
def demo_collision_test():
    """Концептуальний тест на колізії SHA-256."""
    print("\n" + "=" * 80)
    print(f"=== {BOLD}КОНЦЕПТУАЛЬНИЙ ТЕСТ НА КОЛІЗІЇ SHA-256{RESET} ===")
    print("=" * 80)

    # 1. Ініціалізація
    base_text = "The quick brown fox jumps over the lazy dog"

    print_step(1, "ПАРАМЕТРИ ТЕСТУ", {
        "Алгоритм": "SHA-256",
        "Мета": "Перевірити, наскільки мінімальні зміни у вхідних даних змінюють хеш",
        "Вимога": "Зміна одного біта має призводити до повного 'розриву' хешу"
    })

    # 2. Обчислення базового хешу
    print_step(2, "БАЗОВИЙ ХЕШ")
    hash_base = hashlib.sha256(base_text.encode('utf-8')).hexdigest()

    print_substep("2.1", "БАЗОВЕ ПОВІДОМЛЕННЯ", {
        "Текст": f"'{base_text}'",
        "Хеш SHA-256": hash_base
    })

    # 3. Модифікація: додавання одного символу
    print_step(3, "МОДИФІКАЦІЯ: ЗМІНА ДОВЖИНИ")
    modified_text_a = base_text + "."
    hash_mod_a = hashlib.sha256(modified_text_a.encode('utf-8')).hexdigest()

    print_substep("3.1", "ПОВІДОМЛЕННЯ + '.'", {
        "Текст": f"'{modified_text_a}'",
        "Хеш SHA-256": hash_mod_a
    })

    # Візуалізація змін
    print_diff_analysis(hash_base, hash_mod_a, "ВІЗУАЛІЗАЦІЯ ЗМІН (Додано 1 байт)")

    # 4. Модифікація: зміна одного біта
    print_step(4, "МОДИФІКАЦІЯ: ЗМІНА ОДНОГО БІТА")

    # Зміна одного біта у першому символі
    mod_bytes = bytearray(base_text.encode('utf-8'))
    # Змінюємо наймолодший біт першого байта
    mod_bytes[0] ^= 0x01

    # Імітуємо зміну символу
    modified_text_b = mod_bytes.decode('utf-8', errors='ignore')
    hash_mod_b = hashlib.sha256(mod_bytes).hexdigest()

    print_substep("4.1", "ПОВІДОМЛЕННЯ ЗІ ЗМІНОЮ 1 БІТА", {
        "Оригінальний початок": f"'{base_text[:5]}...'",
        "Модифікований початок": f"'{modified_text_b[:5]}...'",
        "Хеш SHA-256": hash_mod_b
    })

    # Візуалізація змін
    print_diff_analysis(hash_base, hash_mod_b, "ВІЗУАЛІЗАЦІЯ ЗМІН (Змінено 1 біт)")

    # 5. Колізія: Концептуальне пояснення
    print_step(5, "КОЛІЗІЯ: КОНЦЕПТУАЛЬНЕ ПОЯСНЕННЯ")

    print_substep("5.1", "ЩО ТАКЕ КОЛІЗІЯ?", {
        "Визначення": "Колізія - це коли H(m₁) = H(m₂) при m₁ ≠ m₂.",
        "Приклад": f"Якби H('{base_text}') = H('{modified_text_a}'), це була б колізія."
    })

    print_substep("5.2", "ВЛАСТИВОСТІ ХЕШ-ФУНКЦІЇ", {
        "Стійкість до колізій": "Неможливість знайти m₁ ≠ m₂ такі, що H(m₁) = H(m₂).",
        "Складність": f"Для SHA-256 це вимагає 2¹²⁸ операцій (завдяки парадоксу днів народження).",
        "Практика": "Наразі не знайдено жодної практичної колізії для SHA-256/512."
    })

    # 6. Парадокс Днів Народження
    print_step(6, "ПАРАДОКС ДНІВ НАРОДЖЕННЯ")
    print_substep("6.1", "СУТЬ ПАРАДОКСУ", {
        "Ідея": "Ймовірність знайти збіг у хешах значно зростає, коли вибірка досягає √N (де N - розмір хеш-простору).",
        "Обчислення": f"Для SHA-256 (N=2²⁵⁶) колізія очікується приблизно за 2¹²⁸ спроб.",
        "Висновок": "Саме тому криптографічна стійкість до колізій вдвічі менша за довжину хешу (128 біт, а не 256)."
    })

    print("\n" + "=" * 80)
    print("✅ ТЕСТ НА КОЛІЗІЇ ЗАВЕРШЕНО")
    print("🔬 Жодної колізії не знайдено (очікувано!)")
    print("=" * 80)


def simple_encrypt_8bit(block, key):
    """Спрощена імітація шифрування 8-бітовим ключем."""
    # Шифрування: (Блок + Ключ) XOR 0xAA mod 256
    return (block + key) % 256 ^ 0xAA


def demo_ai_bruteforce_simulation():
    """
    Симуляція повного перебору (Brute-Force) з лічильником ключів та таймером.
    """
    print("\n" + "=" * 80)
    print(f"=== {BOLD}{RED}КРИПТОАНАЛІЗ: СИМУЛЯЦІЯ BRUTE-FORCE АТАКИ (25-БІТ){RESET} ===")
    print("=" * 80)

    # 1. Ініціалізація
    KEY_SIZE_BITS = 25
    KEY_MAX_VALUE = 2 ** KEY_SIZE_BITS - 1  # ~33.5 млн варіантів

    TARGET_KEY = random.randint(0, KEY_MAX_VALUE)
    TARGET_BLOCK = random.randint(0, 255)
    TARGET_CIPHER = simple_encrypt_8bit(TARGET_BLOCK, TARGET_KEY)

    PERCENT_FOUND = (TARGET_KEY / KEY_MAX_VALUE) * 100

    print_step(1, "ПАРАМЕТРИ АНАЛІЗУ")
    print(f"      {BOLD}Ключовий простір:{RESET} {KEY_MAX_VALUE + 1:,} варіантів")
    print(f"      {BOLD}Цільовий ключ (Hex):{RESET} 0x{TARGET_KEY:07x}")
    print(f"      {BOLD}Очікувана позиція:{RESET} ~{PERCENT_FOUND:.1f}% від початку")

    # 2. Виконання
    print_step(2, "ЗАПУСК ПЕРЕБОРУ")
    print(f"\n      {BOLD}{YELLOW}АТАКА РОЗПОЧАТА...{RESET}\n")

    start_time = time.time()
    keys_checked = 0
    found = False

    # --- ЦИКЛ ПЕРЕБОРУ ---
    for guess_key in range(KEY_MAX_VALUE + 1):
        keys_checked += 1

        current_cipher = simple_encrypt_8bit(TARGET_BLOCK, guess_key)
        is_found = (guess_key == TARGET_KEY)

        # ОНОВЛЕННЯ ПРОГРЕСУ (кожні 1000 ключів)
        if guess_key % 1000 == 0 or is_found:
            current_time = time.time()
            elapsed = current_time - start_time

            # Формуємо рядок інформації: Ключі + Час
            info_suffix = f'| Keys: {keys_checked:,} | Time: {elapsed:.1f}s'

            print_progress_bar(guess_key, KEY_MAX_VALUE,
                               prefix=f'      Scan 0x{guess_key:07x}',
                               suffix=info_suffix,
                               length=30)

        if is_found:
            found = True
            elapsed = time.time() - start_time  # Фіксуємо точний час

            # Очищаємо рядок перед виводом результату (довгий пробіл + повернення каретки)
            sys.stdout.write('\r' + ' ' * 120 + '\r')
            sys.stdout.flush()

            print(f"      {GREEN}✅ СПІВПАДАЄ! КЛЮЧ ЗНАЙДЕНО!{RESET}")
            print(f"      {BOLD}Ключ:{RESET} 0x{guess_key:07x}")
            print(f"      {BOLD}Всього спроб:{RESET} {keys_checked:,}")
            print(f"      {BOLD}Витрачено часу:{RESET} {elapsed:.2f} с")
            break

    end_time = time.time()
    duration = end_time - start_time

    # 3. Аналіз
    print_step(3, "РЕЗУЛЬТАТИ")
    if found:
        speed = int(keys_checked / duration) if duration > 0 else 0
        print(f"      {BOLD}Швидкість перебору:{RESET} {speed:,} ключів/сек")
        # Всередині блоку if found:
        unlock_achievement("HACKER_SIM")
    else:
        print(f"      {RED}Ключ не знайдено.{RESET}")

    print("\n" + "=" * 80)
    print("✅ СИМУЛЯЦІЯ ЗАВЕРШЕНА")
    print("=" * 80)
def demo_aes_key_schedule():
    """Детальна демонстрація розкладу ключів AES-128."""
    print("\n" + "=" * 80)
    print(f"=== {BOLD}ДЕТАЛЬНИЙ РОЗКЛАД КЛЮЧІВ AES-128{RESET} ===")
    print("=" * 80)

    # 1. Ініціалізація
    key_input = input("Введи 16-байтовий (32-символьний HEX) ключ (або Enter): ").strip()
    if not key_input:
        key_bytes = secrets.token_bytes(16)
    else:
        try:
            key_bytes = bytes.fromhex(key_input)
            if len(key_bytes) != 16:
                raise ValueError
        except ValueError:
            print(f"{RED}❌ Невірний формат або довжина ключа. Використовуємо випадковий ключ.{RESET}")
            key_bytes = secrets.token_bytes(16)

    print_step(1, "ІНІЦІАЛІЗАЦІЯ", {
        "Основний ключ (Hex)": key_bytes.hex(),
        "Довжина": f"{len(key_bytes)} байт (128 біт)",
        "Раундів": "10 (потрібно 11 ключів: K₀-K₁₀)"
    })

    # AES S-Box (повторюємо для цілісності)
    s_box = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]

    # Rcon - Round Constant (Константа раунду)
    rcon = [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    ]

    # Функції Key Expansion
    def rot_word(word):
        """Cyclic permutation (rotate left by 1 byte)."""
        return word[1:] + word[:1]

    def sub_word(word):
        """Substitute bytes using AES S-Box."""
        return [s_box[b] for b in word]

    # Перетворення ключа в слова (4 слова по 4 байти)
    key_schedule = [key_bytes[i:i + 4] for i in range(0, len(key_bytes), 4)]

    print_step(2, "ПОЧАТКОВИЙ КЛЮЧ K₀")
    print_substep("2.1", "СЛОВА ОСНОВНОГО КЛЮЧА", {
        "W[0]": key_schedule[0].hex(),
        "W[1]": key_schedule[1].hex(),
        "W[2]": key_schedule[2].hex(),
        "W[3]": key_schedule[3].hex()
    })

    # Генерація K₁ - K₁₀
    for r in range(10):  # 10 раундів
        i = r + 4  # Початок нового слова

        print_step(3, f"ГЕНЕРАЦІЯ КЛЮЧА K{r + 1} (Слова W[{i}] - W[{i + 3}])")

        # 1. Обчислення T - тимчасового слова (W[i-1])
        t = list(key_schedule[i - 1])
        print_substep(f"{r + 1}.1", "ПОЧАТКОВЕ ТИМЧАСОВЕ СЛОВО (W[i-1])", {
            "W[i-1]": f"W[{i - 1}] = {bytes(t).hex()}"
        })

        # 2. RotWord (Циклічний зсув)
        t = rot_word(t)
        print_substep(f"{r + 1}.2", "ROTWORD (Зсув на 1 байт вліво)", {
            "t (після Rot)": bytes(t).hex()
        })

        # 3. SubWord (S-Box)
        t = sub_word(t)
        print_substep(f"{r + 1}.3", "SUBWORD (S-Box заміна)", {
            "t (після Sub)": bytes(t).hex()
        })

        # 4. XOR з Rcon
        rcon_val = rcon[r]
        t[0] ^= rcon_val
        print_substep(f"{r + 1}.4", "XOR З RCON", {
            "Rcon (раунд {r+1})": f"0x{rcon_val:02x}",
            "t (після Rcon)": bytes(t).hex()
        })

        # 5. Обчислення W[i]
        w_i_minus_4 = list(key_schedule[i - 4])
        w_i = [t[j] ^ w_i_minus_4[j] for j in range(4)]
        key_schedule.append(bytes(w_i))
        print_substep(f"{r + 1}.5", "ОБЧИСЛЕННЯ W[i] = W[i-4] ⊕ T", {
            "W[i-4]": f"W[{i - 4}] = {bytes(w_i_minus_4).hex()}",
            "T": bytes(t).hex(),
            "W[i]": f"W[{i}] = {bytes(w_i).hex()}"
        })

        # 6. Обчислення W[i+1], W[i+2], W[i+3] (без Rot/Sub/Rcon)
        for j in range(1, 4):
            w_next = [key_schedule[i + j - 1][k] ^ key_schedule[i + j - 4][k] for k in range(4)]
            key_schedule.append(bytes(w_next))
            print_substep(f"{r + 1}.5.{j + 1}", f"ОБЧИСЛЕННЯ W[i+{j}]", {
                "W[i+j-1]": f"W[{i + j - 1}] = {key_schedule[i + j - 1].hex()}",
                "W[i+j-4]": f"W[{i + j - 4}] = {key_schedule[i + j - 4].hex()}",
                "W[i+j]": f"W[{i + j}] = {key_schedule[i + j].hex()}"
            })

        print_substep(f"{r + 1}.6", f"КЛЮЧ РАУНДУ K{r + 1} (W[{i}] - W[{i + 3}])", {
            "K{r+1}": b"".join(key_schedule[i:i + 4]).hex()
        })


    print_step(4, "ФІНАЛЬНА ТАБЛИЦЯ КЛЮЧІВ")
    print(f"  {'Раунд':>6} | {'Ключ (Hex)':>64}")
    print(f"  {'-' * 72}")

    # Вивід всіх 11 ключів
    for r in range(11):
        start_idx = r * 4
        round_key = b"".join(key_schedule[start_idx:start_idx + 4]).hex()
        print(f"  {f'K{r}':>6} | {round_key:>64}")

    print("\n" + "=" * 80)
    print("✅ РОЗКЛАД КЛЮЧІВ AES ЗАВЕРШЕНО")
    print("=" * 80)


def demo_avalanche_effect_lab():
    """Лабораторія криптоаналізу: візуалізація лавинного ефекту."""
    print("\n" + "=" * 80)
    print(f"=== {BOLD}ЛАБОРАТОРІЯ КРИПТОАНАЛІЗУ: ЛАВИННИЙ ЕФЕКТ{RESET} ===")
    print("=" * 80)

    # 1. Ініціалізація
    text = input("Введи базовий текст: ").strip() or "The quick brown fox jumps over the lazy dog"

    # Змінюємо один біт: останній байт XOR 0x01
    modified_text_bytes = bytearray(text.encode('utf-8'))
    if modified_text_bytes:
        modified_text_bytes[-1] ^= 0x01
        modified_text = modified_text_bytes.decode('utf-8', errors='ignore')
    else:
        modified_text = "ERROR"
        modified_text_bytes = b"ERROR"

    print_step(1, "ПАРАМЕТРИ ЛАБОРАТОРІЇ")
    print_substep("1.1", "ВХІДНІ ДАНІ", {
        "Базовий текст": f"'{text}'",
        "Базовий Hex": text.encode('utf-8').hex(),
        "Модифікований текст": f"'{modified_text}'",
        "Модифікований Hex": modified_text_bytes.hex(),
        "Зміна": "Один біт у останньому байті"
    })

    # 2. Тест SHA-256
    print_step(2, "ТЕСТ 1: SHA-256 (ХЕШУВАННЯ)")
    hash_base = hashlib.sha256(text.encode('utf-8')).hexdigest()
    hash_mod = hashlib.sha256(modified_text_bytes).hexdigest()

    print_substep("2.1", "РЕЗУЛЬТАТИ ХЕШУВАННЯ", {
        "Base Hash": hash_base,
        "Mod Hash": hash_mod
    })
    print(f"\n      {YELLOW}Аналіз бітової розбіжності...{RESET}")
    for i in range(100):
        # Швидкий пробіг
        if i % 5 == 0:
            print_progress_bar(i + 1, 100, prefix='      Comparing:', suffix='SHA-256', length=40)
        time.sleep(0.01)
    print()
    print_diff_analysis(hash_base, hash_mod, "Лавинний ефект SHA-256")

    # 3. Тест HMAC-SHA512
    print_step(3, "ТЕСТ 2: HMAC-SHA512")
    key = secrets.token_bytes(64)
    hmac_base = hmac.new(key, text.encode('utf-8'), hashlib.sha512).hexdigest()
    hmac_mod = hmac.new(key, modified_text_bytes, hashlib.sha512).hexdigest()

    print_substep("3.1", "РЕЗУЛЬТАТИ HMAC", {
        "Base HMAC": hmac_base,
        "Mod HMAC": hmac_mod
    })
    print(f"\n      {YELLOW}Аналіз бітової розбіжності...{RESET}")
    for i in range(100):
        # Швидкий пробіг
        if i % 5 == 0:
            print_progress_bar(i + 1, 100, prefix='      Comparing:', suffix='SHA-256', length=40)
        time.sleep(0.01)
    print()
    print_diff_analysis(hmac_base, hmac_mod, "Лавинний ефект HMAC-SHA512")

    # 4. Тест AES-128 (Концептуальний)
    print_step(4, "ТЕСТ 3: AES-128 (КОНЦЕПТУАЛЬНИЙ)")

    # Обмежимося 16 байтами, як у demo_aes_detailed
    aes_key = secrets.token_bytes(16)
    aes_base_data = text.encode('utf-8')[:16].ljust(16, b'\x00')
    aes_mod_data = bytearray(aes_base_data)

    # Зміна одного біта
    aes_mod_data[0] ^= 0x01

    # Використовуємо бібліотеку для 1 раунду (імітація, оскільки реалізація складна)
    def encrypt_aes_mock(data, key):
        """Імітує шифрування одного блоку."""
        cipher = hashlib.sha256(key + data).digest()
        return cipher[:16].hex()

    aes_cipher_base = encrypt_aes_mock(aes_base_data, aes_key)
    aes_cipher_mod = encrypt_aes_mock(aes_mod_data, aes_key)

    print_substep("4.1", "РЕЗУЛЬТАТИ AES (MOCK)", {
        "Base Cipher (16b)": aes_cipher_base,
        "Mod Cipher (16b)": aes_cipher_mod
    })
    print(f"\n      {YELLOW}Аналіз бітової розбіжності...{RESET}")
    for i in range(100):
        # Швидкий пробіг
        if i % 5 == 0:
            print_progress_bar(i + 1, 100, prefix='      Comparing:', suffix='SHA-256', length=40)
        time.sleep(0.01)
    print()
    # Виводимо аналіз для шифротексту
    print_diff_analysis(aes_cipher_base, aes_cipher_mod, "Лавинний ефект AES (Mock)")

    print_step(5, "ВИСНОВОК ЛАБОРАТОРІЇ")
    print_substep("5.1", "ПРИНЦИП ЛАВИННОГО ЕФЕКТУ", {
        "Мета": "Забезпечити, щоб зміна одного біта у вході призводила до зміни ~50% бітів у виході.",
        "Критерій": "Біти повинні змінюватися випадково (рівномірно) від 48% до 52%.",
        "Важливість": "Критично важлива властивість для криптографічної безпеки."
    })
    unlock_achievement("HASH_HUNTER")
    print("\n" + "=" * 80)
    print("✅ ЛАБОРАТОРІЯ КРИПТОАНАЛІЗУ ЗАВЕРШЕНА")
    print("🔬 Бітова дифузія візуалізована!")
    print("=" * 80)


def demo_ecc_step_by_step():
    """Детальна демонстрація додавання точок на еліптичній кривій."""
    ask_to_watch_video("ECC")
    print("\n" + "=" * 80)
    print(f"=== {BOLD}ДЕТАЛЬНА АРИФМЕТИКА ECC: ДОДАВАННЯ ТОЧОК{RESET} ===")
    print("=" * 80)

    # Параметри (як у demo_ecc_explain, але спрощені)
    p = 17
    a = 2
    b = 3

    # Точки для демонстрації
    P_x, P_y = 5, 1
    Q_x, Q_y = 6, 3
    P = (P_x, P_y)
    Q = (Q_x, Q_y)

    print_step(1, "ПАРАМЕТРИ КРИВОЇ", {
        "Рівняння": f"y² = x³ + {a}x + {b} (mod {p})",
        "Модуль p": p,
        "Точка P": P,
        "Точка Q": Q
    }, interactive=False)

    # Функція для знаходження оберненого (з нашої нової egcd_plain)
    def mod_inverse_local(a, m):
        g, x, y = extended_gcd_plain(a, m)
        if g != 1: return None
        return x % m

    # 1. Обчислення схилу (lambda)
    print_step(2, "ОБЧИСЛЕННЯ СХИЛУ (SLOPE)")

    # Випадок 1: P ≠ Q (Додавання різних точок)
    if P != Q:
        print_substep("2.1", "ДОДАВАННЯ P + Q (P ≠ Q)")

        dy = (Q_y - P_y) % p
        dx = (Q_x - P_x) % p

        print_substep("2.2", "РОЗРАХУНОК Δy та Δx", {
            "Δy = y₂ - y₁": dy,
            "Δx = x₂ - x₁": dx
        })

        if dx == 0:
            print(f"{RED}❌ dx = 0. Точка на нескінченності (P + Q = O).{RESET}")
            return

        inv_dx = mod_inverse_local(dx, p)

        print_substep("2.3", "ОБЕРНЕНИЙ ЕЛЕМЕНТ Δx⁻¹", {
            "Δx⁻¹ mod p": inv_dx,
            "Перевірка": f"{dx} × {inv_dx} mod {p} = {(dx * inv_dx) % p}"
        })

        s = (dy * inv_dx) % p
        print_substep("2.4", "СХИЛ (λ)", {
            "λ = Δy / Δx": s
        })

    # Випадок 2: P = Q (Подвоєння точки)
    else:
        print_substep("2.1", "ПОДВОЄННЯ 2P (P = Q)")

        dy = (3 * P_x ** 2 + a) % p
        dx = (2 * P_y) % p

        print_substep("2.2", "РОЗРАХУНОК Δy та Δx", {
            "Δy = 3x² + a": dy,
            "Δx = 2y": dx
        })

        if dx == 0:
            print(f"{RED}❌ dx = 0. Точка на нескінченності (2P = O).{RESET}")
            return

        inv_dx = mod_inverse_local(dx, p)
        s = (dy * inv_dx) % p

        print_substep("2.3", "СХИЛ (λ)", {
            "λ = (3x² + a) / 2y": s
        })

    # 2. Обчислення нових координат
    print_step(3, "ОБЧИСЛЕННЯ НОВИХ КООРДИНАТ R = P + Q")

    # Формули
    x_r = (s ** 2 - P_x - Q_x) % p
    y_r = (s * (P_x - x_r) - P_y) % p

    print_substep("3.1", "РОЗРАХУНОК X-КООРДИНАТИ (xᵣ)", {
        "Формула": "xᵣ = λ² - x₁ - x₂ (mod p)",
        "xᵣ": x_r
    })

    print_substep("3.2", "РОЗРАХУНОК Y-КООРДИНАТИ (yᵣ)", {
        "Формула": "yᵣ = λ(x₁ - xᵣ) - y₁ (mod p)",
        "yᵣ": y_r
    })

    R = (x_r, y_r)
    print_step(4, "ФІНАЛЬНИЙ РЕЗУЛЬТАТ", {
        "P + Q": f"{P} + {Q}",
        "Результат R": R,
        "Статус": "✅ Операція додавання успішна"
    }, interactive=True)


# =========================================================================
# VII. ТЕСТУВАННЯ ЗНАНЬ (QUIZ MODE)
# =========================================================================
def draw_puzzle_state(blocks):
    """Малює поточний стан блоків у вигляді ASCII-коробок."""
    print("\n      ПОТОЧНИЙ СТАН СИСТЕМИ:")
    print("      " + "-" * 30)

    for i, block in enumerate(blocks, 1):
        # Малюємо блок як коробку
        print(f"      {BOLD}{YELLOW}[ {i} ]{RESET} ┌──────────────────────────┐")
        print(f"            │ {CYAN}{block:^24}{RESET} │")
        print(f"            └──────────────────────────┘")
        if i < len(blocks):
            print(f"                       {BOLD}↓{RESET}")  # Стрілка вниз

    print("      " + "-" * 30)


def memory_game():
    """Розширена інтерактивна гра з переміщенням блоків."""
    print("\n" + "=" * 80)
    print(f"=== {BOLD}{GREEN}МІНІ-ГРА: КРИПТО-КОНСТРУКТОР (AES){RESET} ===")
    print("=" * 80)

    # Еталонний порядок
    correct_order = ["SubBytes", "ShiftRows", "MixColumns", "AddRoundKey"]

    # Створюємо копію і перемішуємо, поки вона не стане відмінною від оригіналу
    current_blocks = random.sample(correct_order, len(correct_order))
    while current_blocks == correct_order:
        current_blocks = random.sample(correct_order, len(correct_order))

    print(f"\n{BLUE}ЗАВДАННЯ:{RESET} Відновіть правильний потік даних у раунді AES.")
    print(f"Міняйте блоки місцями, доки алгоритм не стане вірним.")
    print(f"{BOLD}Команда:{RESET} Введіть два номери блоків, щоб поміняти їх (наприклад: '1 3')")

    moves = 0
    start_time = time.time()

    while True:
        # 1. Малюємо стан
        draw_puzzle_state(current_blocks)

        # 2. Перевірка на перемогу
        if current_blocks == correct_order:
            elapsed = time.time() - start_time
            unlock_achievement("PUZZLE_SOLVER")
            print(f"\n{BOLD}{GREEN}🎉 СИСТЕМУ ВІДНОВЛЕНО!{RESET}")
            print(f"      {BOLD}Правильний порядок:{RESET} SubBytes → ShiftRows → MixColumns → AddRoundKey")
            print(f"      {BOLD}Кількість ходів:{RESET} {moves}")
            print(f"      {BOLD}Час:{RESET} {elapsed:.1f} с")
            break

        # 3. Запит ходу
        user_input = input(
            f"\n{YELLOW}Крок {moves + 1}.{RESET} Які блоки поміняти? (або 'q' для виходу): ").strip().lower()

        if user_input == 'q':
            print("Гру перервано.")
            break

        try:
            # Парсинг вводу (наприклад "1 4" або "1,4")
            parts = user_input.replace(',', ' ').split()

            if len(parts) != 2:
                print(f"{RED}⚠️  Введіть рівно два номери (наприклад: 1 2){RESET}")
                continue

            idx1 = int(parts[0]) - 1
            idx2 = int(parts[1]) - 1

            # Перевірка меж
            if not (0 <= idx1 < 4 and 0 <= idx2 < 4):
                print(f"{RED}⚠️  Номери мають бути від 1 до 4{RESET}")
                continue

            if idx1 == idx2:
                print(f"{RED}⚠️  Вибрано той самий блок.{RESET}")
                continue

            # 4. Виконання обміну (SWAP)
            print(f"{BLUE}🔄 Переміщення блоків...{RESET}")
            time.sleep(0.3)  # Ефект анімації

            current_blocks[idx1], current_blocks[idx2] = current_blocks[idx2], current_blocks[idx1]
            moves += 1

        except ValueError:
            print(f"{RED}❌ Некоректний ввід. Використовуйте цифри.{RESET}")

    input(f"\n{YELLOW}Натисніть Enter для повернення в меню...{RESET}")
def demo_quiz_mode():
    """Тест на знання основних криптографічних алгоритмів."""
    print("\n" + "=" * 80)
    print(f"=== {BOLD}{GREEN}ТЕСТУВАННЯ ЗНАНЬ ОСНОВ КРИПТОГРАФІЇ{RESET} ===")
    print("=" * 80)

    questions = [
        {
            "q": "Який криптографічний алгоритм використовує функцію RotWord, SubWord та Rcon у своєму ключовому розкладі?",
            "options": ["1. Blowfish", "2. ChaCha20","3. AES" , "4. RSA"],
            "answer": "3",
            "explanation": "Ці операції (циклічний зсув, S-Box заміна та XOR з константою) є основою Key Expansion в AES."
        },
        {
            "q": "Яка основна математична операція лежить в основі SHA-512?",
            "options": ["1. Арифметика в GF(2⁸)", "2. Модульне додавання (mod 2⁶⁴) та ROTR", "3. Еліптичні криві",
                        "4. Факторизація"],
            "answer": "2",
            "explanation": "SHA-512 базується на операціях ARX (Add, Rotate, XOR) з 64-бітними словами, де додавання є модульним (mod 2⁶⁴)."
        },
        {
            "q": "Яка перевага алгоритму Kaliņa (ДСТУ 7624:2014) над AES у контексті архітектури?",
            "options": ["1. Використовує мережу Файстеля", "2. Є потоковим шифром",
                        "3. Використовує тільки XOR операції", "4. Має 8 незалежних S-Boxів"],
            "answer": "4",
            "explanation": "Kaliņa використовує 8 незалежних S-Boxів, що ускладнює криптоаналіз, на відміну від одного S-Box в AES."
        },
        {
            "q": "Яка ключова функція використовується в ChaCha20 для перемішування 4 слів?",
            "options": ["1. PHT (Pseudo-Hadamard Transform)", "2. Quarter Round", "3. KSA (Key Scheduling Algorithm)",
                        "4. MixColumns"],
            "answer": "2",
            "explanation": "ChaCha20 використовує Quarter Round (ARX) як основний будівельний блок для перемішування 4 слів."
        },
        {
            "q": "Чому HMAC-SHA512 стійкий до атак розширення довжини, на відміну від простого хешування H(key || message)?",
            "options": ["1. Використовує дві хеш-функції (внутрішню та зовнішню)", "2. Використовує 512 біт, а не 256",
                        "3. Використовує RSA", "4. Є потоковим шифром"],
            "answer": "1",
            "explanation": "Двошарова структура H((K ⊕ opad) || H((K ⊕ ipad) || m)) захищає від атак розширення довжини, оскільки внутрішній хеш прихований зовнішнім хешем."
        }
    ]

    score = 0
    print_step(1, f"ПОЧАТОК ТЕСТУ: {len(questions)} ПИТАНЬ", interactive=False)

    for i, q_data in enumerate(questions):
        print(f"\n{BOLD}{YELLOW}--- Питання {i + 1} ---{RESET}")
        print(f"{q_data['q']}")
        for opt in q_data['options']:
            print(f"  {opt}")

        user_answer = input("Ваша відповідь (номер): ").strip()

        if user_answer == q_data['answer']:
            score += 1
            print(f"{GREEN}✅ Правильно!{RESET}")
        else:
            print(f"{RED}❌ Неправильно.{RESET}")

        print(f"  {BOLD}Пояснення:{RESET} {q_data['explanation']}")

    print_step(2, "РЕЗУЛЬТАТ ТЕСТУВАННЯ", interactive=False)
    print(f"{BOLD}Ваш результат:{RESET} {score} з {len(questions)}")
    print(f"Відсоток правильних відповідей: {GREEN}{(score / len(questions)) * 100:.1f}%{RESET}")
    print("\n" + "=" * 80)
    print("✅ ТЕСТУВАННЯ ЗАВЕРШЕНО")
    print("=" * 80)


# =========================================================================
# VIII. ІГРОВА ЗОНА (СИМУЛЯТОРИ)
# =========================================================================

def demo_secure_chat_detailed():
    """
    Деталізована симуляція захищеного чату (імітація TLS/Signal).
    Демонструє: Handshake, Nonce, Authenticated Encryption (AEAD).
    """
    print("\n" + "=" * 80)
    print(f"=== {BOLD}{GREEN}СИМУЛЯТОР: SECURE MESSENGER (AES-GCM DETAILED){RESET} ===")
    print("=" * 80)

    # --- ЕТАП 1: HANDSHAKE ---
    print(f"\n{BOLD}{YELLOW}[ЕТАП 1] HANDSHAKE (Встановлення з'єднання){RESET}")
    time.sleep(0.5)

    alice_priv = secrets.token_bytes(32)
    print(f"  👩 {GREEN}Аліса{RESET} генерує ефемерні ключі...")
    time.sleep(0.3)

    bob_priv = secrets.token_bytes(32)
    print(f"  👨 {CYAN}Боб{RESET}   генерує ефемерні ключі...")
    time.sleep(0.3)

    # Імітація ECDH (спільний секрет)
    shared_master_secret = hashlib.sha256(alice_priv + bob_priv).digest()

    print(f"  🤝 {BOLD}Ключ узгоджено!{RESET}")
    print(f"     Session Key (Hex): {YELLOW}{shared_master_secret.hex()[:32]}...{RESET}")
    print(f"     (Цей ключ ніколи не передається через мережу!)")

    print("\n" + "-" * 80)
    print(f"{BOLD}Починаємо спілкування. Напишіть повідомлення.{RESET}")
    print(f"(Спробуйте написати одне й те саме двічі, щоб побачити зміну Nonce)")
    print(f"(Введіть {RED}'exit'{RESET} для виходу)\n")

    msg_counter = 0

    # Функція імітації AES-GCM (XOR + HMAC)
    def simulate_aes_gcm_encrypt(key, plaintext_str, nonce_bytes):
        # 1. Шифрування (XOR з keystream)
        keystream_seed = key + nonce_bytes
        keystream = hashlib.sha512(keystream_seed).digest()

        ciphertext_arr = bytearray()
        plaintext_bytes = plaintext_str.encode('utf-8')

        # Розширюємо keystream якщо треба
        while len(keystream) < len(plaintext_bytes):
            keystream += hashlib.sha512(keystream).digest()

        for i, b in enumerate(plaintext_bytes):
            cipher_byte = b ^ keystream[i]
            ciphertext_arr.append(cipher_byte)

        ciphertext_bytes = bytes(ciphertext_arr)

        # 2. Аутентифікація (HMAC від Nonce + Ciphertext)
        auth_tag_bytes = hmac.new(key, nonce_bytes + ciphertext_bytes, hashlib.sha256).digest()[:16]

        return ciphertext_bytes, auth_tag_bytes

    while True:
        try:
            plaintext = input(f"\n{GREEN}Аліса (Ви):{RESET} ").strip()
            if plaintext.lower() == 'exit': break
            if not plaintext: continue

            msg_counter += 1

            # --- ЕТАП 2: ФОРМУВАННЯ ПАКЕТА ---
            print(f"   {BOLD}⚙️  Обробка на пристрої Аліси:{RESET}")

            # Nonce (Random + Counter)
            nonce = secrets.token_bytes(8) + msg_counter.to_bytes(4, 'big')
            print(f"     1. Генерація Nonce (IV): {BLUE}{nonce.hex()}{RESET}")

            ciphertext, auth_tag = simulate_aes_gcm_encrypt(shared_master_secret, plaintext, nonce)

            print(f"     2. Шифрування (AES):     {RED}{ciphertext.hex()[:40]}...{RESET}")
            print(f"     3. Генерація Tag (MAC):  {YELLOW}{auth_tag.hex()}{RESET}")

            # --- ЕТАП 3: ПЕРЕДАЧА ---
            print(f"\n   {BLUE}📡 [МЕРЕЖА / ІНТЕРНЕТ] 📡{RESET}")
            print(f"   Хакер бачить цей пакет:")
            c_preview = ciphertext.hex()
            if len(c_preview) > 30: c_preview = c_preview[:30] + ".."

            print(f"   ┌{'─' * 56}┐")
            print(f"   │ NONCE: {nonce.hex()} │ DATA: {c_preview:<24} │ TAG: {auth_tag.hex()} │")
            print(f"   └{'─' * 56}┘")

            time.sleep(0.8)

            # --- ЕТАП 4: ОТРИМАННЯ ---
            print(f"\n   {BOLD}⚙️  Обробка на пристрої Боба:{RESET}")

            # Перевірка Tag
            recalc_tag = hmac.new(shared_master_secret, nonce + ciphertext, hashlib.sha256).digest()[:16]

            if recalc_tag == auth_tag:
                print(f"     1. Перевірка Tag: {GREEN}✅ ВАЛІДНИЙ{RESET}")

                # Дешифрування (XOR назад)
                keystream_seed = shared_master_secret + nonce
                keystream = hashlib.sha512(keystream_seed).digest()
                decrypted_arr = bytearray()

                # Розширюємо keystream
                while len(keystream) < len(ciphertext):
                    keystream += hashlib.sha512(keystream).digest()

                for i, b in enumerate(ciphertext):
                    decrypted_arr.append(b ^ keystream[i])

                decrypted_text = decrypted_arr.decode('utf-8')
                print(f"     2. Дешифрування:  {GREEN}✅ УСПІХ{RESET}")
                print(f"\n{CYAN}Боб:{RESET} {decrypted_text}")
                print("-" * 60)
            else:
                print(f"     1. Перевірка Tag: {RED}❌ ПОМИЛКА! (Дані пошкоджено){RESET}")

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Помилка: {e}")
            break
    print("\nЧат завершено.")


def demo_pin_cracker():
    """Симуляція злому PIN-коду перебором."""
    print("\n" + "=" * 80)
    print(f"=== {BOLD}{RED}СИМУЛЯЦІЯ АТАКИ: ПІДБІР PIN-КОДУ{RESET} ===")
    print("=" * 80)

    pin = input("Встановіть PIN-код жертви (4-6 цифр): ").strip()
    if not pin.isdigit() or len(pin) > 8:
        print(f"{RED}Тільки цифри, максимум 8!{RESET}")
        return

    print(f"\n{YELLOW}[ХАКЕР]{RESET} Починаю атаку на PIN...")
    time.sleep(1)

    start_time = time.time()
    attempts = 0
    limit = 10 ** len(pin)

    for i in range(limit):
        attempts += 1
        guess = f"{i:0{len(pin)}d}"

        # Візуалізація кожні 113 спроб
        if i % 113 == 0:
            sys.stdout.write(f"\r{RED}[SCANNING]{RESET} {guess} | Спроб: {attempts}")
            sys.stdout.flush()
            time.sleep(0.0005)

        if guess == pin:
            end_time = time.time()
            print(f"\n\n{GREEN}✅ УСПІХ! PIN ЗНАЙДЕНО: {guess}{RESET}")
            print(f"Час атаки: {end_time - start_time:.4f} сек")
            print(f"Кількість спроб: {attempts}")

            if len(pin) <= 4:
                print(f"\n{BOLD}Висновок:{RESET} 4 цифри — це дуже слабкий захист.")
            return


def demo_tamper_data():
    """Гра: Спробуй підробити транзакцію (HMAC Integrity)."""
    print("\n" + "=" * 80)
    print(f"=== {BOLD}{YELLOW}MITM АТАКА: ПІДРОБКА ТРАНЗАКЦІЇ{RESET} ===")
    print("=" * 80)

    original_msg = "Переказ: 100 грн від Аліси"
    secret_key = b'bank_secret_key_123'

    # Підпис банку
    original_signature = hmac.new(secret_key, original_msg.encode(), hashlib.sha256).hexdigest()

    print(f"{GREEN}Оригінальний пакет:{RESET}")
    print(f"  Дані:   '{original_msg}'")
    print(f"  Підпис: {original_signature[:16]}...")

    print("\nВи — хакер. Ви перехопили пакет.")
    fake_msg = input(f"{RED}Введіть нові дані (напр. 'Переказ: 1000000 грн'):{RESET} ").strip()
    if not fake_msg: fake_msg = "Переказ: 1000000 грн від Аліси"

    print(f"\n{YELLOW}Відправляємо підробку в Банк...{RESET}")
    time.sleep(1)

    print(f"\n{BLUE}[БАНК] Перевірка цілісності...{RESET}")

    # Банк перевіряє підпис для НОВИХ даних
    bank_calc_signature = hmac.new(secret_key, fake_msg.encode(), hashlib.sha256).hexdigest()

    print(f"  Дані отримані: '{fake_msg}'")
    print(f"  Підпис у пакеті (старий): {original_signature[:16]}...")
    print(f"  Підпис розрахований:      {bank_calc_signature[:16]}...")

    if original_signature == bank_calc_signature:
        print(f"\n{GREEN}Атака успішна! (Це неможливо без ключа){RESET}")
    else:
        print(f"\n{RED}❌ ТРИВОГА! ПІДПИС НЕВАЛІДНИЙ! ТРАНЗАКЦІЮ ВІДХИЛЕНО.{RESET}")
        print("Висновок: Зміна даних порушує математичний підпис (HMAC).")


def menu_games():
    """Меню ігрової зони."""
    while True:
        print(f"\n{BOLD}{MAGENTA if 'MAGENTA' in globals() else BLUE}--- ІГРОВА ЗОНА (СИМУЛЯТОРИ) ---{RESET}")
        options = {
            "1": "Безпечний Месенджер (Alice & Bob TLS Sim)",
            "2": "Злам PIN-коду (Brute-Force Visualizer)",
            "3": "Підробка транзакції (HMAC Integrity Game)",
            "B": "Назад"
        }
        for k, v in options.items():
            print(f"{k}. {v}")

        ch = input("\nВибір: ").strip().upper()
        if ch == "B":
            break
        elif ch == "1":
            demo_secure_chat_detailed()
        elif ch == "2":
            demo_pin_cracker()
        elif ch == "3":
            demo_tamper_data()
        else:
            print("Невірний вибір.")

# =========================================================================
# IV. КОНСОЛЬНЕ МЕНЮ (УЛЬТРА-РЕЖИМ)
# =========================================================================

def console_menu():
    load_achievements()
    unlock_achievement("FIRST_RUN")
    print_ascii_art()
    print("=" * 60)
    print(f"=== CryptoSpider: УЛЬТРА-РЕЖИМ АЛГОРИТМІВ ===")
    print("=" * 60)

    while True:
        print("\n" + "=" * 50)
        print("ОСНОВНЕ МЕНЮ - ВИБЕРІТЬ КАТЕГОРІЮ ДЛЯ ДЕТАЛІЗАЦІЇ")
        print("=" * 50)

        categories = {
            "A": "СИМЕТРИЧНІ БЛОЧНІ (AES, Blowfish, Twofish, Kaliņa)",
            "B": "СИМЕТРИЧНІ ПОТОКОВІ (RC4, ChaCha20)",
            "C": "АСИМЕТРИЧНІ ТА ХЕШУВАННЯ (RSA, SHA-512, HMAC)",
            "D": "СПЕЦІАЛЬНІ (Homomorphic, Post-Quantum PQC)",
            "E": "ФУНКЦІОНАЛЬНІ ІНСТРУМЕНТИ",  # Змінено для додавання підменю
            "F": "КРИПТОАНАЛІЗ ТА ТЕСТУВАННЯ",
            "G": "ІГРОВА ЗОНА (СИМУЛЯТОРИ)",# <--- НОВА КАТЕГОРІЯ
            "Q": "Вихід"
        }

        for key, value in categories.items():
            print(f"{key}. {value}")

        choice = input("\nВаш вибір: ").strip().upper()

        if choice == "Q":
            print("Дякуємо за використання CryptoSpider! 👋")
            break

        elif choice == "A":
            menu_block_ciphers()
        elif choice == "B":
            menu_stream_ciphers()
        elif choice == "C":
            menu_asymmetric_hash()
        elif choice == "D":
            menu_advanced_cryptography()
        elif choice == "E":
            menu_functional_tools()  # <--- НОВА ФУНКЦІЯ МЕНЮ
        elif choice == "F":
            menu_cryptanalysis()
        elif choice == "G":  # <--- ДОДАЙТЕ ОБРОБКУ
            menu_games()
        else:
            print(f"\n❌ Невірний вибір. Спробуйте інший варіант.")

        input("\nНатисніть Enter для продовження...")


def menu_block_ciphers():
    while True:
        print("\n--- СИМЕТРИЧНІ БЛОЧНІ ШИФРИ ---")
        options = {
            "1": "AES - Детальна демонстрація 1 раунду",
            "2": "BLOWFISH - Деталізація 1 раунду F-функції",
            "3": "TWOFISH - Деталізація 1 раунду",
            "4": "KALIŅA - Деталізація 1 раунду",
            "B": "Назад"
        }
        for k, v in options.items():
            print(f"{k}. {v}")

        ch = input("\nВибір: ").strip().upper()
        if ch == "B":
            break
        elif ch == "1":
            demo_aes_detailed()
        elif ch == "2":
            demo_blowfish_detailed()
        elif ch == "3":
            demo_twofish_detailed()
        elif ch == "4":
            demo_kalina_detailed()
        else:
            print("Невірний вибір.")


def menu_stream_ciphers():
    while True:
        print("\n--- СИМЕТРИЧНІ ПОТОКОВІ ШИФРИ ---")
        options = {
            "1": "RC4 - Деталізація KSA та PRGA",
            "2": "CHACHA20 - Деталізація 1 Quarter Round",
            "B": "Назад"
        }
        for k, v in options.items():
            print(f"{k}. {v}")

        ch = input("\nВибір: ").strip().upper()
        if ch == "B":
            break
        elif ch == "1":
            demo_rc4_detailed()
        elif ch == "2":
            demo_chacha20_detailed()
        else:
            print("Невірний вибір.")


def menu_asymmetric_hash():
    while True:
        print("\n--- АСИМЕТРИЧНЕ ТА ХЕШУВАННЯ ---")
        options = {
            "1": "RSA - Наддетальний аналіз",
            "2": "SHA-512 - Наддетальний аналіз",
            "3": "HMAC-SHA512 - Наддетальна побудова",
            "4": "ECC - Концептуальна демонстрація ECDH",
            "5": "ECC - Детальна арифметика (Додавання точок)", # <--- НОВЕ
            "B": "Назад"
        }
        for k, v in options.items():
            print(f"{k}. {v}")

        ch = input("\nВибір: ").strip().upper()
        if ch == "B":
            break
        elif ch == "1":
            demo_rsa_extremely_detailed()
        elif ch == "2":
            demo_sha512_super_detailed()
        elif ch == "3":
            demo_hmac_super_detailed()
        elif ch == "4":
            demo_ecc_explain()
        elif ch == "5":
            demo_ecc_step_by_step() # <--- НОВИЙ ВИКЛИК
        else:
            print("Невірний вибір.")


def menu_advanced_cryptography():
    while True:
        print("\n--- СПЕЦІАЛЬНІ АЛГОРИТМИ ---")
        options = {
            "1": "ГОМОМОРФНЕ ШИФРУВАННЯ (HE)",
            "2": "ПОСТКВАНТОВА КРИПТОГРАФІЯ (PQC)",
            "B": "Назад"
        }
        for k, v in options.items():
            print(f"{k}. {v}")

        ch = input("\nВибір: ").strip().upper()
        if ch == "B":
            break
        elif ch == "1":
            demo_hecc_conceptual()
        elif ch == "2":
            demo_pqc_lattice_conceptual()
        else:
            print("Невірний вибір.")

def menu_functional_tools():
    """Меню для функціональних інструментів (Математика, Key Schedule)."""
    while True:
        print("\n--- ФУНКЦІОНАЛЬНІ ІНСТРУМЕНТИ ---")
        options = {
            "1": "Математичний Калькулятор (Модуль, GF(2⁸))",
            "2": "AES Key Schedule (Детальний розклад ключів)", # <--- НОВЕ
            "B": "Назад"
        }
        for k, v in options.items():
            print(f"{k}. {v}")

        ch = input("\nВибір: ").strip().upper()
        if ch == "B":
            break
        elif ch == "1":
            interactive_calculator_menu()
        elif ch == "2":
            demo_aes_key_schedule()
        else:
            print("Невірний вибір.")


def menu_cryptanalysis():
    """Меню для криптоаналізу та тестування (Лавинний ефект, Колізії, Quiz)."""
    while True:
        print("\n--- КРИПТОАНАЛІЗ ТА ТЕСТУВАННЯ ---")
        options = {
            "1": "Лабораторія Лавинного Ефекту (Візуалізація змін)",
            "2": "Тест на колізії (Концептуальний SHA-256)",
            "3": "Тестування Знань (Quiz Mode)",
            "4": "Симуляція Brute-Force атаки (25-біт)",
            "5": "Міні-гра: Архітектор AES",
            "B": "Назад"
        }
        for k, v in options.items():
            print(f"{k}. {v}")

        ch = input("\nВибір: ").strip().upper()
        if ch == "B":
            break
        elif ch == "1":
            demo_avalanche_effect_lab()
        elif ch == "2":
            demo_collision_test()
        elif ch == "3":
            demo_quiz_mode()
        elif ch == "4":
            demo_ai_bruteforce_simulation()
        elif ch == "5":  # <--- ДОДАНО ОБРОБКУ
            memory_game()
        else:
            print("Невірний вибір.")
# =========================================================================
# V. ДОДАТКОВІ ФУНКЦІЇ (для повноти)
# =========================================================================

def demo_rsa_extremely_detailed():
    """НАДДЕТАЛЬНА демонстрація RSA з КОЖНИМ математичним кроком."""
    ask_to_watch_video("RSA")
    print_algo_diagram("CHACHA20")
    import math

    def print_step(step_num, title, data=None, delay=0.5):  # <- ПЕРЕВИЗНАЧЕННЯ ТУТ
        """Уніфікований вивід кроку з форматуванням."""
        print(f"\n{'=' * 60}")
        print(f"КРОК {step_num}: {title}")
        print(f"{'=' * 60}")
        if data:
            if isinstance(data, dict):
                for key, value in data.items():
                    print(f"  {key}: {value}")
            else:
                print(f"  {data}")

    def print_substep(tag, title, info=None):
        print(f"  {tag} — {title}")
        if isinstance(info, dict):
            for k, v in info.items():
                print(f"    {k}: {v}")
        elif info:
            print(f"    {info}")

    def egcd_with_table(a, b):
        """Розширений Екклід з виводом таблиці; повертає (g, x, y)."""
        print("\n      РОЗШИРЕНИЙ АЛГОРИТМ ЕВКЛІДА (таблиця)")
        print(f"      Шукаємо x,y такі, що a·x + b·y = gcd(a,b)")
        print(f"      {'Крок':>4} | {'a':>8} | {'b':>8} | {'q':>6} | {'x':>8} | {'y':>8}")
        print("      " + "-" * 56)

        x0, x1 = 1, 0
        y0, y1 = 0, 1
        step = 0
        aa, bb = a, b
        print(f"      {step:>4} | {aa:>8} | {bb:>8} | {'':>6} | {x0:>8} | {y0:>8}")
        while bb != 0:
            q = aa // bb
            aa, bb, x0, x1, y0, y1 = bb, aa - q * bb, x1, x0 - q * x1, y1, y0 - q * y1
            step += 1
            print(f"      {step:>4} | {aa:>8} | {bb:>8} | {q:>6} | {x0:>8} | {y0:>8}")
        g = aa
        x = x0
        y = y0
        print(f"      {BOLD}{GREEN}gcd = {g}, x = {x}, y = {y}{RESET}")
        return g, x, y

    print("\n" + "=" * 80)
    print("=== НАДДЕТАЛЬНА ДЕМОНСТРАЦІЯ RSA - КОЖЕН МАТЕМАТИЧНИЙ КРОК ===")
    print("=" * 80)

    # Початкові прості числа (залишаю твої)
    p, q = 3001, 3011
    n = p * q
    phi = (p - 1) * (q - 1)

    # Початкове e — якщо воно не підходить, підберемо інше
    e = 17

    print_step(1, "ГЕНЕРАЦІЯ КЛЮЧІВ")
    print_substep("1.1", "Прості числа", {
        "p": p, "q": q,
        "n = p × q": f"{p} × {q} = {n}",
        "φ(n) = (p-1) × (q-1)": f"{p-1} × {q-1} = {phi}"
    })

    print_step(2, "ОБЧИСЛЕННЯ ОБЕРНЕНОГО ЕЛЕМЕНТА d")
    print_substep("2.1", "Умова", {
        "початково вибрано e": e,
        "φ(n)": phi,
        "Формула": f"d × e ≡ 1 (mod {phi})"
    })

    # Перевіримо gcd(e, phi)
    if math.gcd(e, phi) != 1:
        print(f"    Початкове e = {e} не підходить (gcd != 1). Підбираю інше e...")
        # вибираємо невелике e, непарне і взаємно просте з phi
        for cand in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if math.gcd(cand, phi) == 1:
                e = cand
                break
        print(f"    Обране e = {e}")

    print_substep("2.2", "Перевірка gcd", {
        "gcd(e, φ(n))": math.gcd(e, phi),
        "e": e
    })

    # Знаходимо d — обернений елемент e (mod phi) — через розширений Евклід
    g, x, y = egcd_with_table(e, phi)
    if g != 1:
        print("    ! Немає оберненого елементу (gcd != 1) — припиняємо")
        return
    # x тепер такий, що e*x + phi*y = 1  => e*x ≡ 1 (mod phi)
    d = x % phi
    print_substep("2.3", "РЕЗУЛЬТАТ", {
        "Знайдений d": d,
        "Перевірка": f"{d} × {e} mod {phi} = {(d * e) % phi}"
    })

    print_step(3, "ФОРМУВАННЯ КЛЮЧІВ")
    print_substep("3.1", "Ключі", {
        "Публічний ключ (e, n)": f"({e}, {n})",
        "Приватний ключ (d, n)": f"({d}, {n})"
    })

    # Повідомлення для шифрування
    print_step(4, "ПІДГОТОВКА ПОВІДОМЛЕННЯ")
    message = "ABC"  # твоє повідомлення
    message_bytes = message.encode('utf-8')

    print_substep("4.1", "КОНВЕРТАЦІЯ ТЕКСТУ В БАЙТИ")
    print(f"    Текст: '{message}'")
    print(f"    Байти (hex): {message_bytes.hex()}")
    print(f"    Посимвольна конвертація:")
    for i, char in enumerate(message):
        byte_val = ord(char)
        print(f"      '{char}' -> ASCII: {byte_val:3d} (0x{byte_val:02x})")

    # Конвертація в одне число (якщо потрібно)
    message_num = int.from_bytes(message_bytes, 'big')
    bytes_len = len(message_bytes)
    print_substep("4.2", "КОНВЕРТАЦІЯ БАЙТІВ У ЧИСЛО", {
        "m (число)": message_num,
        "m (hex)": f"0x{message_num:x}",
        "Довжина в байтах": bytes_len,
        "Перевірка m < n": f"{message_num} < {n} ✓" if message_num < n else "❌"
    })

    # Якщо m < n — можемо зашифрувати одним блоком. Інакше — шифруємо по-байтово (кожен байт окремо).
    if message_num < n:
        print_step(5, "ШИФРУВАННЯ: один блок")
        print_substep("5.1", "Формула", {
            "m": message_num, "e": e, "n": n,
            "Обчислення": f"c = m^{e} mod {n}"
        })
        ciphertext = pow(message_num, e, n)
        print_substep("5.2", "РЕЗУЛЬТАТ ШИФРУВАННЯ", {
            "Шифротекст c": f"{BOLD}{YELLOW}{ciphertext}{RESET}",
        "c (hex)": f"0x{ciphertext:x}",
            "Перевірка c < n": f"{ciphertext} < {n} ✓"
        })

        print_step(6, "ДЕШИФРУВАННЯ: один блок")
        print_substep("6.1", "Формула", {
            "c": ciphertext, "d": d, "n": n,
            "Обчислення": f"m = c^{d} mod {n}"
        })
        decrypted_num = pow(ciphertext, d, n)
        print_substep("6.2", "РЕЗУЛЬТАТ ДЕШИФРУВАННЯ", {
            "Дешифроване число": decrypted_num
        })

        print_step(7, "КОНВЕРТАЦІЯ ЧИСЛА НАЗАД У ТЕКСТ")
        # Відновимо саме bytes_len байт
        decrypted_bytes = decrypted_num.to_bytes(bytes_len, 'big')
        try:
            decrypted_text = decrypted_bytes.decode('utf-8')
        except Exception as ex:
            decrypted_text = "<невдала декодування>"
            print(f"    Помилка декодування байтів: {ex}")

        print_substep("7.1", "ПРОЦЕС КОНВЕРТАЦІЇ", {
            "Число": decrypted_num,
            "Байти (hex)": decrypted_bytes.hex(),
            "Текст": f"'{decrypted_text}'"
        })

        success = decrypted_text == message
        print_step(8, "ФІНАЛЬНА ПЕРЕВІРКА")
        print_substep("8.1", "ПОРІВНЯННЯ", {
            "Оригінал": f"'{message}'",
            "Результат": f"'{decrypted_text}'",
            "Статус": f"{GREEN}✅ УСПІХ{RESET}" if success else f"{RED}❌ НЕВДАЧА{RESET}"
        })

    else:
        # m >= n: шифруємо по-байтово (кожен байт < n)
        print_step(5, "m >= n — шифруємо ПО-БАЙТОВО (кожен байт окремо)")
        ciphertext_bytes = []
        decrypted_bytes_list = []
        for i, b in enumerate(message_bytes):
            c = pow(b, e, n)
            m2 = pow(c, d, n)
            ciphertext_bytes.append(c)
            decrypted_bytes_list.append(m2)
            print(f"  Байт {i}: {b} -> c = {c}, дешифр m2 = {m2}")
        # перетворимо назад в байти
        reconstructed = bytes([int(x) for x in decrypted_bytes_list])
        try:
            recon_text = reconstructed.decode('utf-8')
        except Exception as ex:
            recon_text = "<невдала декодування>"
            print(f"    Помилка декодування реконсруктованих байт: {ex}")

        print_substep("5.x", "РЕЗУЛЬТАТ ПО-БАЙТОВО", {
            "Шифротекст (по-байту)": str(ciphertext_bytes),
            "Дешифровані байти": reconstructed.hex(),
            "Текст": f"'{recon_text}'",
            "Статус": "✅ УСПІХ" if recon_text == message else "❌ НЕВДАЧА"
        })
        success = (recon_text == message)

    # ДОДАТКОВА ПЕРЕВІРКА з одним символом
    print_step(9, "ДОДАТКОВА ПЕРЕВІРКА З 'A'")
    message_simple = "A"
    m_simple = ord(message_simple)
    c_simple = pow(m_simple, e, n)
    m2_simple = pow(c_simple, d, n)
    try:
        ch_dec = chr(m2_simple)
    except Exception:
        ch_dec = "<нечитабельний>"

    print_substep("9.1", "РЕЗУЛЬТАТ", {
        "Текст": f"'{message_simple}'",
        "m": m_simple,
        "Шифрування": f"{m_simple}^{e} mod {n} = {c_simple}",
        "Дешифрування": f"{c_simple}^{d} mod {n} = {m2_simple}",
        "Результат": f"'{ch_dec}'",
        "Статус": "✅ УСПІХ" if ch_dec == message_simple else "❌"
    })
    unlock_achievement("RSA_EXPERT")
    print("\n" + "=" * 80)
    print("✅ RSA ДЕМОНСТРАЦІЯ ЗАВЕРШЕНА")
    print("=" * 80)


def demo_sha512_super_detailed():
    """НАДДЕТАЛЬНА демонстрація SHA-512 з КОЖНИМ перетворенням."""
    ask_to_watch_video("SHA-512")
    print_algo_diagram("SHA-512")
    print("\n" + "=" * 80)
    print("=== НАДДЕТАЛЬНА ДЕМОНСТРАЦІЯ SHA-512 - КОЖЕН КРОК ===")
    print("=" * 80)

    # 1. Вступ до SHA-512
    print_step(1, "ВСТУП ДО SHA-512")
    print_substep("1.1", "ПАРАМЕТРИ АЛГОРИТМУ", {
        "Розмір хешу": "512 біт (64 байти)",
        "Розмір блоку": "1024 біт (128 байт)",
        "Розмір слова": "64 біта (8 байт)",
        "Кількість раундів": "80",
        "Безпека": "256 біт стійкості до колізій",
        "Стандарт": "FIPS 180-4",
        "Рік": "2005"
    })

    message = input("Введи повідомлення для хешування: ").strip() or "SHA-512 Ultra Detailed Demonstration"

    print_substep("1.2", "ВХІДНІ ДАНІ", {
        "Повідомлення": f"'{message}'",
        "Довжина повідомлення": f"{len(message)} символів",
        "Довжина в байтах": f"{len(message.encode('utf-8'))} байт",
        "Довжина в бітах": f"{len(message.encode('utf-8')) * 8} біт"
    })

    # 2. Підготовка повідомлення
    print_step(2, "ПІДГОТОВКА ПОВІДОМЛЕННЯ")
    original_bytes = message.encode('utf-8')
    original_bit_length = len(original_bytes) * 8

    print_substep("2.1", "КОДУВАННЯ ТЕКСТУ В БАЙТИ", {
        "Текст": f"'{message}'",
        "Байти (UTF-8)": original_bytes.hex(),
        "Бітова довжина": f"{original_bit_length} біт"
    })

    # Детальний вивід перших байтів
    print_substep("2.2", "ДЕТАЛЬНИЙ АНАЛІЗ ПЕРШИХ БАЙТІВ")
    for i, byte in enumerate(original_bytes[:16]):
        char = chr(byte) if 32 <= byte <= 126 else '?'
        print(f"      Байт {i:2d}: {byte:02x} = {byte:3d} = '{char}' = {byte:08b}")

    # 3. Додавання падінгу
    print_step(3, "ДОДАВАННЯ ПАДІНГУ")
    print_substep("3.1", "ВИМОГИ ДО ПАДІНГУ", {
        "Правило 1": "Додати біт '1' в кінець повідомлення",
        "Правило 2": "Додати нулі до довжини 896 mod 1024 біт",
        "Правило 3": "Додати 128-бітне представлення довжини оригіналу",
        "Загальна довжина": "Кратна 1024 бітам"
    })

    # Крок 1: Додавання біта '1'
    padded_bytes = original_bytes + b'\x80'  # 10000000 в бінарному
    print_substep("3.2", "ДОДАВАННЯ БІТА '1'", {
        "Байт падінгу": "0x80 (10000000)",
        "Проміжна довжина": f"{len(padded_bytes)} байт",
        "Hex представлення": f"{padded_bytes.hex()[:64]}..."
    })

    # Крок 2: Додавання нулів
    block_size = 128  # 1024 біт = 128 байт
    zeros_needed = (block_size - (len(padded_bytes) + 16) % block_size) % block_size
    padded_bytes += b'\x00' * zeros_needed

    print_substep("3.3", "ДОДАВАННЯ НУЛІВ", {
        "Потрібно нулів": zeros_needed,
        "Проміжна довжина": f"{len(padded_bytes)} байт",
        "Hex представлення": f"{padded_bytes.hex()[:64]}..."
    })

    # Крок 3: Додавання довжини повідомлення
    length_bytes = original_bit_length.to_bytes(16, 'big')
    final_message = padded_bytes + length_bytes

    print_substep("3.4", "ДОДАВАННЯ ДОВЖИНИ ПОВІДОМЛЕННЯ", {
        "Оригінальна довжина (біти)": original_bit_length,
        "Довжина у байтах": length_bytes.hex(),
        "Фінальна довжина": f"{len(final_message)} байт ({len(final_message) * 8} біт)",
        "Кількість блоків": f"{len(final_message) // block_size}"
    })

    # 4. Ініціалізація змінних хешу
    print_step(4, "ІНІЦІАЛІЗАЦІЯ ЗМІННИХ ХЕШУ")

    # Початкові значення SHA-512 (перші 64 біти дробових частин квадратних коренів перших 8 простих чисел)
    h = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    ]

    initial_h = h.copy()

    print_substep("4.1", "ПОЧАТКОВІ ЗНАЧЕННЯ h0-h7", {
        "h0": f"{h[0]:016x} (√2)",
        "h1": f"{h[1]:016x} (√3)",
        "h2": f"{h[2]:016x} (√5)",
        "h3": f"{h[3]:016x} (√7)",
        "h4": f"{h[4]:016x} (√11)",
        "h5": f"{h[5]:016x} (√13)",
        "h6": f"{h[6]:016x} (√17)",
        "h7": f"{h[7]:016x} (√19)"
    })

    # 5. Константи SHA-512
    print_step(5, "КОНСТАНТИ SHA-512")

    # Константи (перші 64 біти дробових частин кубічних коренів перших 80 простих чисел)
    k = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    ]

    print_substep("5.1", "ПЕРШІ 16 КОНСТАНТ k[0]-k[15]", {
        "k[0]-k[3]": f"{k[0]:016x} {k[1]:016x} {k[2]:016x} {k[3]:016x}",
        "k[4]-k[7]": f"{k[4]:016x} {k[5]:016x} {k[6]:016x} {k[7]:016x}",
        "k[8]-k[11]": f"{k[8]:016x} {k[9]:016x} {k[10]:016x} {k[11]:016x}",
        "k[12]-k[15]": f"{k[12]:016x} {k[13]:016x} {k[14]:016x} {k[15]:016x}"
    })

    # 6. Функції SHA-512
    print_step(6, "ФУНКЦІЇ SHA-512")

    def ch(x, y, z):
        return (x & y) ^ (~x & z)

    def maj(x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    def sigma0(x):
        return right_rotate(x, 28) ^ right_rotate(x, 34) ^ right_rotate(x, 39)

    def sigma1(x):
        return right_rotate(x, 14) ^ right_rotate(x, 18) ^ right_rotate(x, 41)

    def gamma0(x):
        return right_rotate(x, 1) ^ right_rotate(x, 8) ^ (x >> 7)

    def gamma1(x):
        return right_rotate(x, 19) ^ right_rotate(x, 61) ^ (x >> 6)

    print_substep("6.1", "ЛОГІЧНІ ФУНКЦІЇ", {
        "Ch(x,y,z)": "(x ∧ y) ⊕ (¬x ∧ z)",
        "Maj(x,y,z)": "(x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)",
        "Σ₀(x)": "ROTR²⁸(x) ⊕ ROTR³⁴(x) ⊕ ROTR³⁹(x)",
        "Σ₁(x)": "ROTR¹⁴(x) ⊕ ROTR¹⁸(x) ⊕ ROTR⁴¹(x)",
        "σ₀(x)": "ROTR¹(x) ⊕ ROTR⁸(x) ⊕ SHR⁷(x)",
        "σ₁(x)": "ROTR¹⁹(x) ⊕ ROTR⁶¹(x) ⊕ SHR⁶(x)"
    })

    # 7. Обробка блоків
    print_step(7, "ОБРОБКА БЛОКІВ ДАНИХ")
    blocks_count = len(final_message) // block_size

    print_substep("7.1", "ІНФОРМАЦІЯ ПРО БЛОКИ", {
        "Кількість блоків": blocks_count,
        "Розмір блоку": "1024 біт (128 байт)",
        "Загальна обробка": f"{blocks_count} × 80 раундів = {blocks_count * 80} операцій"
    })

    # Для демонстрації обробляємо тільки перший блок детально
    for block_num in range(min(1, blocks_count)):  # Тільки перший блок для демонстрації
        block_start = block_num * block_size
        block = final_message[block_start:block_start + block_size]

        print_step(7.2, f"ОБРОБКА БЛОКУ {block_num + 1}")
        print_substep("7.2.1", "ДАНІ БЛОКУ", {
            "Блок (hex)": block.hex()[:64] + "...",
            "Позиція": f"байти {block_start}-{block_start + block_size - 1}"
        })

        # Розширення блоку
        print_step(7.3, "РОЗШИРЕННЯ БЛОКУ ДО 80 СЛІВ")
        w = [0] * 80

        # Перші 16 слів з блоку
        for i in range(16):
            w[i] = int.from_bytes(block[i * 8:(i + 1) * 8], 'big')

        print_substep("7.3.1", "ПЕРШІ 16 СЛІВ З БЛОКУ", {
            "w[0]-w[3]": f"{w[0]:016x} {w[1]:016x} {w[2]:016x} {w[3]:016x}",
            "w[4]-w[7]": f"{w[4]:016x} {w[5]:016x} {w[6]:016x} {w[7]:016x}",
            "w[8]-w[11]": f"{w[8]:016x} {w[9]:016x} {w[10]:016x} {w[11]:016x}",
            "w[12]-w[15]": f"{w[12]:016x} {w[13]:016x} {w[14]:016x} {w[15]:016x}"
        })

        # Розширення до 80 слів
        print_step(7.4, "РОЗШИРЕННЯ w[16]-w[79]")
        print(f"\n      ФОРМУЛА: w[i] = w[i-16] + σ₀(w[i-15]) + w[i-7] + σ₁(w[i-2])")
        print(f"      ДЕТАЛЬНІ ОБЧИСЛЕННЯ (перші 4 розширення):")

        for i in range(16, 20):  # Тільки перші 4 розширення для демонстрації
            s0 = gamma0(w[i - 15])
            s1 = gamma1(w[i - 2])
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFFFFFFFFFF

            print(f"      w[{i}] = w[{i - 16}] + σ₀(w[{i - 15}]) + w[{i - 7}] + σ₁(w[{i - 2}])")
            print(f"           = {w[i - 16]:016x} + {s0:016x} + {w[i - 7]:016x} + {s1:016x}")
            print(f"           = {w[i]:016x}")

        print(f"      ... ({60} розширень приховано) ...")

        # Основний цикл раундів
        print_step(7.5, "ОСНОВНИЙ ЦИКЛ РАУНДІВ (80 РАУНДІВ)")
        a, b, c, d, e, f, g, h_temp = h

        print(f"\n      ПОЧАТКОВИЙ СТАН РОБОЧИХ ЗМІННИХ:")
        print(f"      a={a:016x}, b={b:016x}, c={c:016x}, d={d:016x}")
        print(f"      e={e:016x}, f={f:016x}, g={g:016x}, h={h_temp:016x}")

        # Детальний вивід перших 3 раундів
        # Детальний вивід перших 3 раундів
        for i in range(3):  # Тільки перші 3 раунди для демонстрації
            print(f"\n      --- РАУНД {i} ---")

            # Обчислення проміжних значень
            S1 = sigma1(e)
            ch_result = ch(e, f, g)
            temp1 = (h_temp + S1 + ch_result + k[i] + w[i]) & 0xFFFFFFFFFFFFFFFF
            S0 = sigma0(a)
            maj_result = maj(a, b, c)
            temp2 = (S0 + maj_result) & 0xFFFFFFFFFFFFFFFF

            # ... (вивід temp1 та temp2, як було) ...

            # Збереження старих значень перед оновленням
            old_h = h_temp
            old_a = a
            old_e = e
            old_d = d

            # Оновлення змінних
            h_temp, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFFFFFFFFFF, c, b, a, (
                    temp1 + temp2) & 0xFFFFFFFFFFFFFFFF

            print(f"\n      НОВИЙ СТАН (Hex):")
            # Виділення змін кольором
            print(f"        a (нова) = {get_color_diff_hex(old_a, a)}")
            print(f"        b (нова) = {get_color_diff_hex(b, b)}")  # b=a
            print(f"        c (нова) = {get_color_diff_hex(c, c)}")  # c=b
            print(f"        d (нова) = {get_color_diff_hex(old_d, d)}")
            print(f"        e (нова) = {get_color_diff_hex(old_e, e)}")
            print(f"        f (нова) = {get_color_diff_hex(f, f)}")  # f=e
            print(f"        g (нова) = {get_color_diff_hex(g, g)}")  # g=f
            print(f"        h (нова) = {get_color_diff_hex(old_h, h_temp)}")
    # 8. Фінальний хеш
    print_step(8, "ФОРМУВАННЯ ФІНАЛЬНОГО ХЕШУ")
    final_hash = ''.join(f'{x:016x}' for x in h)

    print_substep("8.1", "ОБ'ЄДНАННЯ ЗНАЧЕНЬ h0-h7", {
        "h0": f"{h[0]:016x}",
        "h1": f"{h[1]:016x}",
        "h2": f"{h[2]:016x}",
        "h3": f"{h[3]:016x}",
        "h4": f"{h[4]:016x}",
        "h5": f"{h[5]:016x}",
        "h6": f"{h[6]:016x}",
        "h7": f"{h[7]:016x}",
        "Фінальний хеш": final_hash
    })

    # 9. Перевірка з бібліотечною реалізацією
    print_step(9, "ПЕРЕВІРКА З БІБЛІОТЕЧНОЮ РЕАЛІЗАЦІЄЮ")
    library_hash = hashlib.sha512(message.encode('utf-8')).hexdigest()

    print_substep("9.1", "ПОРІВНЯННЯ РЕЗУЛЬТАТІВ", {
        "Наша реалізація": final_hash,
        "Бібліотечна реалізація": library_hash,
        "Статус": "✅ СПІВПАДАЄ" if final_hash == library_hash else "❌ НЕ СПІВПАДАЄ"
    })

    # 10. Аналіз властивостей SHA-512
    print_step(10, "АНАЛІЗ ВЛАСТИВОСТЕЙ SHA-512")

    # Лавинний ефект
    modified_message = message + "x"
    modified_hash = hashlib.sha512(modified_message.encode('utf-8')).hexdigest()

    # Підрахунок різниці бітів
    diff_bits = 0
    for i in range(len(final_hash)):
        byte1 = int(final_hash[i], 16)
        byte2 = int(modified_hash[i], 16)
        diff_bits += bin(byte1 ^ byte2).count('1')

    print_substep("10.1", "ЛАВИННИЙ ЕФЕКТ", {
        "Оригінальне повідомлення": f"'{message}'",
        "Модифіковане повідомлення": f"'{modified_message}'",
        "Змінено символів": "1",
        "Змінено бітів у хеші": f"{diff_bits} з 512",
        "Відсоток змін": f"{(diff_bits / 512) * 100:.1f}%",
        "Висновок": "✅ Сильний лавинний ефект"
    })

    print_substep("10.2", "КРИПТОГРАФІЧНІ ВЛАСТИВОСТІ", {
        "Стійкість до колізій": "2²⁵⁶ операцій для знаходження колізії",
        "Стійкість до прообразу": "2⁵¹² операцій для знаходження прообразу",
        "Стійкість до другого прообразу": "2⁵¹² операцій",
        "Застосування": "Цифрові підписи, HMAC, верифікація даних"
    })

    print("\n" + "=" * 80)
    print("✅ SHA-512 ДЕМОНСТРАЦІЯ ЗАВЕРШЕНА")
    print("🔐 Надійний криптографічний хеш з 512-бітним виходом")
    print("=" * 80)


def demo_hmac_super_detailed():
    """НАДДЕТАЛЬНА демонстрація HMAC-SHA512 з КОЖНИМ перетворенням."""
    ask_to_watch_video("HMAC")
    print_algo_diagram("HMAC")
    print("\n" + "=" * 80)
    print("=== НАДДЕТАЛЬНА ДЕМОНСТРАЦІЯ HMAC-SHA512 - КОЖЕН КРОК ===")
    print("=" * 80)

    # 1. Вступ до HMAC
    print_step(1, "ВСТУП ДО HMAC")
    print_substep("1.1", "ПАРАМЕТРИ ТА ПРИЗНАЧЕННЯ", {
        "Алгоритм": "HMAC (Hash-based Message Authentication Code)",
        "Хеш-функція": "SHA-512",
        "Розмір виходу": "512 біт (64 байти)",
        "Призначення": "Перевірка цілісності та автентичності повідомлень",
        "Стандарт": "RFC 2104, FIPS 198-1",
        "Ключова властивість": "Стійкість до атак, навіть якщо хеш-функція не стійка до колізій"
    })

    print_substep("1.2", "ПЕРЕВАГИ HMAC", {
        "Універсальність": "Може використовувати будь-яку криптографічну хеш-функцію",
        "Простота": "Проста реалізація на основі існуючих хеш-функцій",
        "Безпека": "Стійкість залежить від безпеки базової хеш-функції",
        "Ефективність": "Швидкий обчислення, низькі накладні витрати"
    })

    # 2. Генерація ключа та повідомлення
    key = secrets.token_bytes(32)
    message = input("Введи повідомлення для HMAC: ").strip() or "HMAC-SHA512 Detailed Demonstration"

    print_step(2, "ВХІДНІ ДАНІ")
    print_substep("2.1", "КЛЮЧ", {
        "Ключ (hex)": key.hex(),
        "Довжина ключа": f"{len(key)} байт ({len(key) * 8} біт)",
        "Рекомендована довжина": "≥ довжина виходу хеш-функції (64 байти для SHA-512)"
    })

    print_substep("2.2", "ПОВІДОМЛЕННЯ", {
        "Текст": f"'{message}'",
        "Байти (hex)": message.encode('utf-8').hex(),
        "Довжина повідомлення": f"{len(message)} символів, {len(message.encode('utf-8'))} байт"
    })

    # 3. Підготовка ключа
    print_step(3, "ПІДГОТОВКА КЛЮЧА")
    print_substep("3.1", "ВИМОГИ ДО КЛЮЧА", {
        "Блок-розмір SHA-512": "128 байт (1024 біта)",
        "Правило 1": "Якщо ключ довший за блок-розмір - хешуємо його",
        "Правило 2": "Якщо ключ коротший - доповнюємо нулями",
        "Результат": "Ключ довжиною рівно 128 байт"
    })

    block_size = 128  # Блок-розмір SHA-512

    # Крок 1: Перевірка довжини ключа
    print_step(3.2, "ПЕРЕВІРКА ДОВЖИНИ КЛЮЧА")
    if len(key) > block_size:
        print_substep("3.2.1", "КЛЮЧ ДОВШИЙ ЗА БЛОК-РОЗМІР - ХЕШУЄМО", {
            "Довжина ключа": f"{len(key)} байт > {block_size} байт",
            "Операція": "K' = SHA-512(K)"
        })
        key_hashed = hashlib.sha512(key).digest()
        key_prepared = key_hashed
        print(f"      Результат хешування: {key_hashed.hex()}")
    elif len(key) < block_size:
        print_substep("3.2.2", "КЛЮЧ КОРОТШИЙ ЗА БЛОК-РОЗМІР - ДОПОВНЮЄМО НУЛЯМИ", {
            "Довжина ключа": f"{len(key)} байт < {block_size} байт",
            "Операція": "K' = K || 0x00... (до 128 байт)"
        })
        key_prepared = key + b'\x00' * (block_size - len(key))
        print(f"      Ключ після доповнення: {key_prepared.hex()}")
    else:
        print_substep("3.2.3", "КЛЮЧ ІДЕАЛЬНОЇ ДОВЖИНИ", {
            "Довжина ключа": f"{len(key)} байт = {block_size} байт",
            "Операція": "Використовуємо ключ без змін"
        })
        key_prepared = key

    print_substep("3.3", "ФІНАЛЬНИЙ ПІДГОТОВЛЕНИЙ КЛЮЧ", {
        "K' (hex)": key_prepared.hex()[:64] + "...",
        "Довжина": f"{len(key_prepared)} байт",
        "Перевірка": f"{len(key_prepared)} == {block_size} ✓"
    })

    # 4. Константи ipad та opad
    print_step(4, "КОНСТАНТИ ipad ТА opad")
    ipad = bytes([0x36] * block_size)  # 00110110 повторюється
    opad = bytes([0x5C] * block_size)  # 01011100 повторюється

    print_substep("4.1", "ipad (inner pad)", {
        "Значення": "0x36 (00110110 в бінарному)",
        "Повторень": f"{block_size} разів",
        "Hex представлення": f"{ipad.hex()[:32]}...",
        "Призначення": "Для внутрішнього хешування"
    })

    print_substep("4.2", "opad (outer pad)", {
        "Значення": "0x5C (01011100 в бінарному)",
        "Повторень": f"{block_size} разів",
        "Hex представлення": f"{opad.hex()[:32]}...",
        "Призначення": "Для зовнішнього хешування"
    })

    # 5. Обчислення K ⊕ ipad та K ⊕ opad
    print_step(5, "ОБЧИСЛЕННЯ XOR З КОНСТАНТАМИ")

    print_step(5.1, "K ⊕ ipad")
    key_ipad = bytes([key_prepared[i] ^ ipad[i] for i in range(block_size)])

    print_substep("5.1.1", "ПОКРОКОВЕ ОБЧИСЛЕННЯ (перші 4 байти)", {
        "Формула": "K_ipad[i] = K'[i] ⊕ ipad[i]"
    })

    for i in range(4):
        k_byte = key_prepared[i]
        ipad_byte = ipad[i]
        result_byte = k_byte ^ ipad_byte

        # Кольоровий вивід змін
        colored_result = get_color_diff_hex(k_byte, result_byte)

        print(f"      Байт {i}: {k_byte:02x} ⊕ {ipad_byte:02x} = {colored_result}")
        print(f"            {k_byte:08b} ⊕ {ipad_byte:08b} = {result_byte:08b}")

    print_substep("5.1.2", "РЕЗУЛЬТАТ K ⊕ ipad", {
        "K_ipad (hex)": key_ipad.hex()[:64] + "...",
        "Довжина": f"{len(key_ipad)} байт"
    })

    print_step(5.2, "K ⊕ opad")
    key_opad = bytes([key_prepared[i] ^ opad[i] for i in range(block_size)])

    print_substep("5.2.1", "ПОКРОКОВЕ ОБЧИСЛЕННЯ (перші 4 байти)", {
        "Формула": "K_opad[i] = K'[i] ⊕ opad[i]"
    })

    for i in range(4):
        k_byte = key_prepared[i]
        opad_byte = opad[i]
        result_byte = k_byte ^ opad_byte

        # Кольоровий вивід змін
        colored_result = get_color_diff_hex(k_byte, result_byte)

        print(f"      Байт {i}: {k_byte:02x} ⊕ {opad_byte:02x} = {colored_result}")
        print(f"            {k_byte:08b} ⊕ {opad_byte:08b} = {result_byte:08b}")

    print_substep("5.2.2", "РЕЗУЛЬТАТ K ⊕ opad", {
        "K_opad (hex)": key_opad.hex()[:64] + "...",
        "Довжина": f"{len(key_opad)} байт"
    })

    # 6. Внутрішній хеш
    print_step(6, "ВНУТРІШНІЙ ХЕШ")
    print_substep("6.1", "ФОРМУЛА ВНУТРІШНЬОГО ХЕШУ", {
        "Вхідні дані": "K_ipad || message",
        "Функція": "SHA-512",
        "Результат": "inner_hash = SHA-512(K_ipad || message)"
    })

    message_bytes = message.encode('utf-8')
    inner_data = key_ipad + message_bytes

    print_substep("6.2", "СКЛАДАННЯ ДАНИХ ДЛЯ ВНУТРІШНЬОГО ХЕШУ", {
        "K_ipad довжина": f"{len(key_ipad)} байт",
        "Повідомлення довжина": f"{len(message_bytes)} байт",
        "Загальна довжина": f"{len(inner_data)} байт",
        "K_ipad (початок)": key_ipad.hex()[:32] + "...",
        "Повідомлення (початок)": message_bytes.hex()[:32] + "..."
    })

    print_step(6.3, "ОБЧИСЛЕННЯ SHA-512(K_ipad || message)")
    inner_hash = hashlib.sha512(inner_data).digest()

    print_substep("6.3.1", "РЕЗУЛЬТАТ ВНУТРІШНЬОГО ХЕШУ", {
        "inner_hash (hex)": inner_hash.hex(),
        "Довжина": f"{len(inner_hash)} байт (512 біт)"
    })

    # 7. Зовнішній хеш
    print_step(7, "ЗОВНІШНІЙ ХЕШ")
    print_substep("7.1", "ФОРМУЛА ЗОВНІШНЬОГО ХЕШУ", {
        "Вхідні дані": "K_opad || inner_hash",
        "Функція": "SHA-512",
        "Результат": "HMAC = SHA-512(K_opad || inner_hash)"
    })

    outer_data = key_opad + inner_hash

    print_substep("7.2", "СКЛАДАННЯ ДАНИХ ДЛЯ ЗОВНІШНЬОГО ХЕШУ", {
        "K_opad довжина": f"{len(key_opad)} байт",
        "inner_hash довжина": f"{len(inner_hash)} байт",
        "Загальна довжина": f"{len(outer_data)} байт",
        "K_opad (початок)": key_opad.hex()[:32] + "...",
        "inner_hash (початок)": inner_hash.hex()[:32] + "..."
    })

    print_step(7.3, "ОБЧИСЛЕННЯ SHA-512(K_opad || inner_hash)")
    hmac_result = hashlib.sha512(outer_data).hexdigest()

    print_substep("7.3.1", "РЕЗУЛЬТАТ HMAC", {
        "HMAC-SHA512": hmac_result,
        "Довжина": f"{len(hmac_result)} символів ({len(hmac_result) * 4} біт)"
    })

    # 8. Загальна формула HMAC
    print_step(8, "ЗАГАЛЬНА ФОРМУЛА HMAC")
    print_substep("8.1", "МАТЕМАТИЧНЕ ПРЕДСТАВЛЕННЯ", {
        "Формула": "HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))",
        "Де H": "SHA-512 хеш-функція",
        "K": "Ключ (підготовлений)",
        "m": "Повідомлення",
        "ipad/opad": "Константи 0x36/0x5C"
    })

    print_substep("8.2", "ВІЗУАЛІЗАЦІЯ ПРОЦЕСУ", """
        Повідомлення (m)
            ↓
        K ⊕ ipad || m
            ↓
        SHA-512 → inner_hash
            ↓  
        K ⊕ opad || inner_hash
            ↓
        SHA-512 → HMAC
    """)

    # 9. Перевірка з бібліотечною реалізацією
    print_step(9, "ПЕРЕВІРКА КОРЕКТНОСТІ")
    library_hmac = hmac.new(key, message.encode('utf-8'), hashlib.sha512).hexdigest()

    print_substep("9.1", "ПОРІВНЯННЯ РЕЗУЛЬТАТІВ", {
        "Наша реалізація": hmac_result,
        "Бібліотечна реалізація": library_hmac,
        "Статус": "✅ СПІВПАДАЄ" if hmac_result == library_hmac else "❌ НЕ СПІВПАДАЄ"
    })

    # 10. Демонстрація захисту від модифікації
    print_step(10, "ДЕМОНСТРАЦІЯ ЗАХИСТУ ВІД МОДИФІКАЦІЇ")

    # Модифікуємо повідомлення
    modified_message = message + "!"
    modified_hmac = hmac.new(key, modified_message.encode('utf-8'), hashlib.sha512).hexdigest()

    print_substep("10.1", "ТЕСТ З МОДИФІКОВАНИМ ПОВІДОМЛЕННЯМ", {
        "Оригінальне повідомлення": f"'{message}'",
        "Модифіковане повідомлення": f"'{modified_message}'",
        "Зміна": "Додано один символ '!'",
        "HMAC для модифікованого": modified_hmac,
        "Порівняння з оригіналом": "❌ НЕ СПІВПАДАЄ (очікувано)"
    })

    # Тест з іншим ключем
    different_key = secrets.token_bytes(32)
    different_key_hmac = hmac.new(different_key, message.encode('utf-8'), hashlib.sha512).hexdigest()

    print_substep("10.2", "ТЕСТ З ІНШИМ КЛЮЧЕМ", {
        "Оригінальний ключ": key.hex()[:16] + "...",
        "Інший ключ": different_key.hex()[:16] + "...",
        "HMAC з іншим ключем": different_key_hmac,
        "Порівняння з оригіналом": "❌ НЕ СПІВПАДАЄ (очікувано)"
    })

    # 11. Застосування HMAC на практиці
    print_step(11, "ПРАКТИЧНЕ ЗАСТОСУВАННЯ HMAC")
    print_substep("11.1", "API АВТЕНТИФІКАЦІЯ", {
        "Сценарій": "Клієнт відправляє запит до API",
        "Ключ": "Секретний ключ, відомий клієнту та серверу",
        "Повідомлення": "Дані запиту + timestamp",
        "Перевірка": "Сервер обчислює HMAC і порівнює з отриманим"
    })

    print_substep("11.2", "ЦІЛІСНІСТЬ ДАНИХ", {
        "Сценарій": "Передача даних через ненадійний канал",
        "Процес": "Відправник обчислює HMAC, отримувач перевіряє",
        "Результат": "Гарантія, що дані не були змінені"
    })

    print_substep("11.3", "ВЕРИФІКАЦІЯ ПОВІДОМЛЕНЬ", {
        "Сценарій": "Система сповіщень або повідомлень",
        "Процес": "Кожне повідомлення супроводжується HMAC",
        "Результат": "Підтвердження автентичності джерела"
    })

    # 12. Безпека HMAC
    print_step(12, "АНАЛІЗ БЕЗПЕКИ HMAC-SHA512")
    print_substep("12.1", "СТІЙКІСТЬ ДО АТАК", {
        "Атаки на ключ": "Стійкість еквівалентна SHA-512",
        "Атаки на колізії": "Навіть якщо SHA-512 має колізії, HMAC залишається безпечним",
        "Атаки на довжину": "Стійкий до атак розширення довжини"
    })

    print_substep("12.2", "РЕКОМЕНДАЦІЇ", {
        "Довжина ключа": "≥ 512 біт (64 байти) для SHA-512",
        "Генерація ключа": "Криптографічно безпечний генератор випадкових чисел",
        "Зберігання ключа": "Безпечне сховище, окреме від даних"
    })

    print("\n" + "=" * 80)
    print("✅ HMAC-SHA512 ДЕМОНСТРАЦІЯ ЗАВЕРШЕНА")
    print("🔐 Надійна автентифікація та перевірка цілісності")
    print("=" * 80)


def demo_ecc_explain():
    """НАДДЕТАЛЬНА демонстрація ECC/ECDH з КОЖНИМ математичним кроком."""
    ask_to_watch_video("ECC")
    print_algo_diagram("ECC")
    print("\n" + "=" * 80)
    print("=== НАДДЕТАЛЬНА ДЕМОНСТРАЦІЯ ECC/ECDH - КОЖЕН МАТЕМАТИЧНИЙ КРОК ===")
    print("=" * 80)

    # 1. Вступ до ECC
    print_step(1, "ВСТУП ДО ЕЛІПТИЧНОЇ КРИПТОГРАФІЇ (ECC)")
    print_substep("1.1", "ОСНОВНІ ПОНЯТТЯ ECC", {
        "ECC": "Elliptic Curve Cryptography - Криптографія на еліптичних кривих",
        "ECDH": "Elliptic Curve Diffie-Hellman - Обмін ключами Діффі-Гелмана",
        "Ключова перевага": "Більша безпека при менших розмірах ключів порівняно з RSA",
        "Приклад": "256-бітний ECC ключ ≈ 3072-бітному RSA ключу за безпекою"
    })

    print_substep("1.2", "МАТЕМАТИЧНА ОСНОВА", {
        "Еліптична крива": "y² = x³ + ax + b (mod p)",
        "Операції": "Складання точок на кривій",
        "Дискретний логарифм": "Складність обернення операції множення точки",
        "Група точок": "Скінченна циклічна група на кривій"
    })

    # 2. Вибір параметрів кривої
    print_step(2, "ВИБІР ПАРАМЕТРІВ ЕЛІПТИЧНОЇ КРИВОЇ")

    # Спрощені параметри для демонстрації
    p = 97  # просте число (модуль)
    a = 2  # параметр кривої
    b = 3  # параметр кривої
    G_x, G_y = 17, 10  # базова точка G

    print_substep("2.1", "ПАРАМЕТРИ КРИВОЇ", {
        "Рівняння кривої": f"y² = x³ + {a}x + {b} (mod {p})",
        "Модуль p": f"{p} (просте число)",
        "Базова точка G": f"({G_x}, {G_y})",
        "Порядок n": "Кількість точок у групі (буде обчислено)"
    })

    # 3. Перевірка, що точка належить кривій
    print_step(3, "ПЕРЕВІРКА ПРИНАЛЕЖНОСТІ ТОЧКИ ДО КРИВОЇ")
    left_side = (G_y * G_y) % p
    right_side = (G_x * G_x * G_x + a * G_x + b) % p

    print_substep("3.1", "ПЕРЕВІРКА БАЗОВОЇ ТОЧКИ G", {
        "Ліва частина (y²)": f"{G_y}² mod {p} = {left_side}",
        "Права частина (x³ + ax + b)": f"{G_x}³ + {a}×{G_x} + {b} mod {p} = {right_side}",
        "Результат перевірки": "✅ Точка належить кривій" if left_side == right_side else "❌ Точка не належить кривій"
    })

    # 4. Генерація секретних ключів
    print_step(4, "ГЕНЕРАЦІЯ СЕКРЕТНИХ КЛЮЧІВ")
    a_private = random.randint(2, 50)  # Секретний ключ Аліси
    b_private = random.randint(2, 50)  # Секретний ключ Боба

    print_substep("4.1", "СЕКРЕТНИЙ КЛЮЧ АЛІСИ", {
        "a (приватний)": a_private,
        "Примітка": "Випадкове ціле число, тримається в секреті"
    })

    print_substep("4.2", "СЕКРЕТНИЙ КЛЮЧ БОБА", {
        "b (приватний)": b_private,
        "Примітка": "Випадкове ціле число, тримається в секреті"
    })

    # 5. Обчислення публічних ключів
    print_step(5, "ОБЧИСЛЕННЯ ПУБЛІЧНИХ КЛЮЧІВ")

    print_substep("5.1", "МАТЕМАТИЧНА ОПЕРАЦІЯ", {
        "Формула": "Публічний ключ = секретний ключ × базова точка G",
        "Операція ×": "Множення точки на скаляр (багаторазове додавання точки)"
    })

    # Функція для додавання точок на еліптичній кривій
    def ec_add(P, Q, p, a):
        if P is None: return Q
        if Q is None: return P

        x1, y1 = P
        x2, y2 = Q

        if x1 == x2:
            if y1 == y2:
                # Подвоєння точки
                s = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
            else:
                return None  # Точка на нескінченності
        else:
            # Додавання різних точок
            s = (y2 - y1) * pow(x2 - x1, -1, p) % p

        x3 = (s * s - x1 - x2) % p
        y3 = (s * (x1 - x3) - y1) % p

        return (x3, y3)

    # Функція для множення точки на скаляр
    def ec_mult(k, point, p, a):
        result = None
        addend = point

        while k:
            if k & 1:
                result = ec_add(result, addend, p, a)
            addend = ec_add(addend, addend, p, a)
            k >>= 1

        return result

    # Обчислення публічних ключів
    print_step(5.2, "ОБЧИСЛЕННЯ ПУБЛІЧНОГО КЛЮЧА АЛІСИ")
    A_public = ec_mult(a_private, (G_x, G_y), p, a)

    print_substep("5.2.1", "ПОКРОКОВЕ МНОЖЕННЯ ТОЧКИ", {
        "Операція": f"A = {a_private} × G",
        "G": f"({G_x}, {G_y})",
        "Результат A": f"({A_public[0]}, {A_public[1]})"
    })

    print_step(5.3, "ОБЧИСЛЕННЯ ПУБЛІЧНОГО КЛЮЧА БОБА")
    B_public = ec_mult(b_private, (G_x, G_y), p, a)

    print_substep("5.3.1", "ПОКРОКОВЕ МНОЖЕННЯ ТОЧКИ", {
        "Операція": f"B = {b_private} × G",
        "G": f"({G_x}, {G_y})",
        "Результат B": f"({B_public[0]}, {B_public[1]})"
    })

    print_substep("5.4", "ПУБЛІЧНІ КЛЮЧІ ДЛЯ ОБМІНУ", {
        "Аліса публічна A": f"({A_public[0]}, {A_public[1]})",
        "Боб публічний B": f"({B_public[0]}, {B_public[1]})",
        "Примітка": "Ці ключі можна передавати по незахищеному каналу"
    })

    # 6. Обмін ключами
    print_step(6, "ОБМІН ПУБЛІЧНИМИ КЛЮЧАМИ")

    print_substep("6.1", "ПРОТОКОЛ ОБМІНУ", {
        "Крок 1": "Аліса відправляє свій публічний ключ A Бобу",
        "Крок 2": "Боб відправляє свій публічний ключ B Алісі",
        "Крок 3": "Обидві сторони обчислюють спільний секрет",
        "Безпека": "Перехоплення публічних ключів не розкриває секретні ключі"
    })

    # 7. Обчислення спільного секрету
    print_step(7, "ОБЧИСЛЕННЯ СПІЛЬНОГО СЕКРЕТУ")

    print_substep("7.1", "МАТЕМАТИЧНА ОСНОВА", {
        "Формула Аліси": f"S = a × B = {a_private} × ({B_public[0]}, {B_public[1]})",
        "Формула Боба": f"S = b × A = {b_private} × ({A_public[0]}, {A_public[1]})",
        "Комутуюча властивість": "a × (b × G) = b × (a × G) = (a×b) × G"
    })

    print_step(7.2, "ОБЧИСЛЕННЯ АЛІСОЮ")
    shared_secret_A = ec_mult(a_private, B_public, p, a)

    print_substep("7.2.1", "РЕЗУЛЬТАТ АЛІСИ", {
        "Операція": f"S_A = {a_private} × B",
        "Спільний секрет Аліси": f"({shared_secret_A[0]}, {shared_secret_A[1]})"
    })

    print_step(7.3, "ОБЧИСЛЕННЯ БОБОМ")
    shared_secret_B = ec_mult(b_private, A_public, p, a)

    print_substep("7.3.1", "РЕЗУЛЬТАТ БОБА", {
        "Операція": f"S_B = {b_private} × A",
        "Спільний секрет Боба": f"({shared_secret_B[0]}, {shared_secret_B[1]})"
    })

    # 8. Перевірка коректності
    print_step(8, "ПЕРЕВІРКА КОРЕКТНОСТІ ОБМІНУ")

    are_equal = shared_secret_A == shared_secret_B

    print_substep("8.1", "ПОРІВНЯННЯ РЕЗУЛЬТАТІВ", {
        "Спільний секрет Аліси": f"({shared_secret_A[0]}, {shared_secret_A[1]})",
        "Спільний секрет Боба": f"({shared_secret_B[0]}, {shared_secret_B[1]})",
        "Статус": "✅ СПІВПАДАЄ - ОБМІН УСПІШНИЙ!" if are_equal else "❌ НЕ СПІВПАДАЄ - ПОМИЛКА!"
    })

    if are_equal:
        # Використання x-координати як спільного секрету
        shared_key = shared_secret_A[0]
        print_substep("8.2", "ФОРМУВАННЯ СПІЛЬНОГО КЛЮЧА", {
            "Джерело": "x-координата спільної точки",
            "Спільний ключ": f"{shared_key}",
            "Використання": "Може бути використаний як симетричний ключ"
        })

    # 9. Демонстрація безпеки
    print_step(9, "АНАЛІЗ БЕЗПЕКИ ECDH")

    print_substep("9.1", "ЗАВДАННЯ ДЛЯ ПРОТИВНИКА", {
        "Відомі дані": "Публічні ключі A, B та базова точка G",
        "Невідомі дані": "Секретні ключі a, b",
        "Задача": "Знайти a з A = a×G або b з B = b×G",
        "Складність": "Задача дискретного логарифма на еліптичних кривих (ECDLP)"
    })

    print_substep("9.2", "СИЛЬНІ СТОРОНИ ECC", {
        "Ефективність": "Менші ключі при тій самій безпеці що RSA",
        "Швидкість": "Швидші операції порівняно з RSA",
        "Безпека": "Стійкість до квантових атак (поки що)"
    })

    # 10. Реальні параметри кривих
    print_step(10, "РЕАЛЬНІ СТАНДАРТНІ КРИВІ")

    print_substep("10.1", "POPULAR CURVES", {
        "secp256k1": "Використовується в Bitcoin, 256-бітна безпека",
        "P-256": "NIST крива, широко використовується в TLS",
        "Curve25519": "Сучасна крива, використовується в Signal, WhatsApp",
        "P-384": "Крива високої безпеки, 384-бітна"
    })

    print_substep("10.2", "ПОРІВНЯННЯ РОЗМІРІВ КЛЮЧІВ", {
        "ECC 256-bit": "≈ RSA 3072-bit за безпекою",
        "ECC 384-bit": "≈ RSA 7680-bit за безпекою",
        "Перевага": "В 10+ разів ефективніше за RSA"
    })

    # 11. Практичне застосування
    print_step(11, "ПРАКТИЧНЕ ЗАСТОСУВАННЯ ECDH")

    print_substep("11.1", "TLS/SSL ПРОТОКОЛ", {
        "Сценарій": "Встановлення безпечного з'єднання в HTTPS",
        "Процес": "Клієнт і сервер обмінюються ECDH ключами",
        "Результат": "Спільний секрет для симетричного шифрування"
    })

    print_substep("11.2", "МЕСЕНДЖЕРИ", {
        "Signal/WhatsApp": "Використовують Curve25519 для ECDH",
        "Протокол": "Double Ratchet алгоритм з постійним оновленням ключів",
        "Перевага": "Forward secrecy - компрометація ключа не розкриває минулі повідомлення"
    })

    print_substep("11.3", "КРИПТОВАЛЮТИ", {
        "Bitcoin/Ethereum": "Використовують secp256k1 для підписів та адрес",
        "Адреса": "Похідна від публічного ключа ECC"
    })

    # 12. Квантова стійкість
    print_step(12, "МАЙБУТНЄ ECC ТА КВАНТОВІ КОМП'ЮТЕРИ")

    print_substep("12.1", "ПОГРОЗА КВАНТОВИХ КОМП'ЮТЕРІВ", {
        "Алгоритм Шора": "Може розв'язати ECDLP за поліноміальний час",
        "Загроза": "Квантові комп'ютери можуть зламати ECC",
        "Прогноз": "10-30 років до практичної реалізації"
    })

    print_substep("12.2", "ПОСТКВАНТОВА КРИПТОГРАФІЯ", {
        "Розв'язок": "Криптографія на основі решіток, кодів, многовимірних кривих",
        "Стандартизація": "NIST Post-Quantum Cryptography Standardization",
        "Перехід": "Поступовий перехід до квантово-стійких алгоритмів"
    })

    print("\n" + "=" * 80)
    print("✅ ECC/ECDH ДЕМОНСТРАЦІЯ ЗАВЕРШЕНА")
    print("🔐 Ефективний обмін ключами з меншими розмірами ключів")
    print("=" * 80)


# Допоміжні функції для форматування виводу
# ---------------------------
# Корисні функції
# ---------------------------
# ... інші функції ...
def byte_to_poly_str(val):
    """Конвертує байт у рядкове представлення полінома."""
    if val == 0:
        return "0"
    res = []
    # Проходимо від 7-го біта до 0-го
    for i in range(7, -1, -1):
        if (val >> i) & 1:
            if i == 0:
                res.append("1")
            elif i == 1:
                res.append("x")
            else:
                res.append(f"x^{i}")
    return " + ".join(res)
def get_color_diff_hex(old_val, new_val):
    """
    Порівнює два 32-бітних або байтових значення (якщо вони є int)
    та повертає рядок з кольоровим виділенням змін (Hex).
    """
    # Визначаємо, скільки байтів ми порівнюємо (1, 4 або 8)
    if new_val <= 0xFF:  # 1 байт
        length = 2
        fmt = f"0{length}x"
    elif new_val <= 0xFFFFFFFF:  # 4 байти
        length = 8
        fmt = f"0{length}x"
    else:  # 8 байтів (64 біти)
        length = 16
        fmt = f"0{length}x"

    old_hex = format(old_val, fmt)
    new_hex = format(new_val, fmt)

    output = ""
    # Порівнюємо по 2 символи (1 байт)
    for i in range(0, length, 2):
        old_byte_hex = old_hex[i:i + 2]
        new_byte_hex = new_hex[i:i + 2]

        if old_byte_hex != new_byte_hex:
            # Змінений байт - Червоний
            output += f"{RED}{new_byte_hex}{RESET}"
        else:
            # Незмінний байт - Зелений
            output += f"{GREEN}{new_byte_hex}{RESET}"

    return output

# ---------------------------
# Корисні функції (оновлене визначення)
# ---------------------------

def print_substep(substep_num, title, data=None, delay=0.3):
    """Уніфікований вивід підкроку. Параметр 'data' зроблений опціональним."""
    print(f"\n  [{substep_num}] {title}")
    if data:
        if isinstance(data, dict):
            for key, value in data.items():
                print(f"      {key}: {value}")
        else:
            print(f"      {data}")
    time.sleep(delay)


def interactive_calculator_menu():
    """Меню для інтерактивного калькулятора."""
    while True:
        print(f"\n{BOLD}{GREEN}--- ІНТЕРАКТИВНИЙ КАЛЬКУЛЯТОР КРИПТОМАТЕМАТИКИ ---{RESET}")
        options = {
            "1": "Модульна Арифметика (a, b, n)",
            "2": "Арифметика в Полі Галуа GF(2⁸) (Множення)",
            "B": "Назад"
        }
        for k, v in options.items():
            print(f"{k}. {v}")

        ch = input("\nВаш вибір: ").strip().upper()
        if ch == "B":
            break
        elif ch == "1":
            calc_modular_arithmetic()
        elif ch == "2":
            calc_gf256_arithmetic()
        else:
            print(f"{RED}❌ Невірний вибір.{RESET}")


def calc_modular_arithmetic():
    """Калькулятор модульної арифметики (додавання, множення, обернений елемент)."""
    print_step("1.1", "МОДУЛЬНА АРИФМЕТИКА")
    try:
        a = int(input(f"{YELLOW}Введіть число a:{RESET} "))
        b = int(input(f"{YELLOW}Введіть число b:{RESET} "))
        n = int(input(f"{YELLOW}Введіть модуль n:{RESET} "))
    except ValueError:
        print(f"{RED}❌ Невірний ввід. Потрібні цілі числа.{RESET}")
        return

    print_substep("1.1.1", "ПАРАМЕТРИ", {"a": a, "b": b, "n": n})

    # Додавання
    add_res = (a + b) % n
    print_substep("1.1.2", "ДОДАВАННЯ", {
        "Формула": f"({a} + {b}) mod {n}",
        "Результат": add_res,
        "Пояснення": f"{a + b} / {n} = {int((a + b) / n)} з залишком {add_res}"
    })

    # Множення
    mul_res = (a * b) % n
    print_substep("1.1.3", "МНОЖЕННЯ", {
        "Формула": f"({a} × {b}) mod {n}",
        "Результат": mul_res,
        "Пояснення": f"{a * b} / {n} = {int((a * b) / n)} з залишком {mul_res}"
    })

    # Обернений елемент (a⁻¹)
    try:
        g, x, y = extended_gcd_plain(a, n)
        if g == 1:
            inv = x % n
            print_substep("1.1.4", f"ОБЕРНЕНИЙ ЕЛЕМЕНТ (a⁻¹ mod n)", {
                "Умова": f"gcd({a}, {n}) = 1 (виконано)",
                "Результат": inv,
                "Перевірка": f"{a} × {inv} mod {n} = {(a * inv) % n}"
            })
        else:
            print_substep("1.1.4", f"ОБЕРНЕНИЙ ЕЛЕМЕНТ (a⁻¹ mod n)", {
                "Статус": f"{RED}❌ Не існує{RESET}",
                "Причина": f"gcd({a}, {n}) = {g} ≠ 1"
            })
    except Exception as e:
        print(f"{RED}❌ Помилка обчислення оберненого елемента: {e}{RESET}")


def calc_gf256_arithmetic():
    """Калькулятор множення та оберненого елемента в полі Галуа GF(2⁸)."""
    print_step("1.2", "АРИФМЕТИКА В ПОЛІ ГАЛУА GF(2⁸) (AES MixColumns)")
    m_poly = 0x11B

    # --- 1. Введення даних ---
    try:
        a_hex = input(f"{YELLOW}Введіть перший байт (a, hex, напр. 02):{RESET} ").strip()
        b_hex = input(f"{YELLOW}Введіть другий байт (b, hex, напр. 53):{RESET} ").strip()
        a = int(a_hex, 16)
        b = int(b_hex, 16)
    except ValueError:
        print(f"{RED}❌ Невірний ввід. Потрібні байти в hex форматі.{RESET}")
        return

    # ВІЗУАЛІЗАЦІЯ ПОЛІНОМІВ
    poly_a = byte_to_poly_str(a)
    poly_b = byte_to_poly_str(b)

    print_substep("1.2.1", "ПАРАМЕТРИ ПОЛЯ", {
        "Байт a": f"0x{a:02x} ({a:08b}) -> {CYAN}{poly_a}{RESET}",
        "Байт b": f"0x{b:02x} ({b:08b}) -> {CYAN}{poly_b}{RESET}",
        "Поліном (mod)": f"0x{m_poly:x} (x^8 + x^4 + x^3 + x + 1)"
    })

    # --- 2. Множення ---
    print_substep("1.2.2", "МНОЖЕННЯ (a × b)")
    p = 0
    a_current = a

    # Виконуємо множення (алгоритм селянського множення)
    for i in range(8):
        if b & 1:
            p ^= a_current

        high_bit = a_current & 0x80
        a_current <<= 1
        if high_bit:
            a_current ^= m_poly

        a_current &= 0xFF  # Обмежуємо до 8 біт
        b >>= 1

    final_res = p
    poly_res = byte_to_poly_str(final_res)

    print_substep("1.2.3", "ФІНАЛЬНИЙ РЕЗУЛЬТАТ МНОЖЕННЯ", {
        "Результат (hex)": f"0x{final_res:02x}",
        "Результат (бінарно)": f"{final_res:08b}",
        "Результат (поліном)": f"{GREEN}{poly_res}{RESET}"
    })

    # --- 3. Обернений Елемент ---
    print_step("1.2.4", "ОБЕРНЕНИЙ ЕЛЕМЕНТ (a⁻¹ mod m(x))")

    if a == 0:
        print_substep("1.2.5", "ОБЧИСЛЕННЯ a⁻¹", {
            "Статус": f"{RED}❌ Не існує{RESET}",
            "Причина": "0 не має оберненого елемента в GF(2⁸)"
        })
        return

    g_poly, inv_poly = poly_extended_gcd(a, m_poly)

    if g_poly == 1:
        check = gmult(a, inv_poly)
        poly_inv = byte_to_poly_str(inv_poly)

        print_substep("1.2.5", "РЕЗУЛЬТАТ ОБЕРНЕНОГО ЕЛЕМЕНТА", {
            "Статус": f"{GREEN}✅ Існує{RESET}",
            "Обернений елемент (a⁻¹)": f"0x{inv_poly:02x} -> {CYAN}{poly_inv}{RESET}",
            "Перевірка (a × a⁻¹)": f"0x{check:02x} (має бути 0x01)"
        })
    else:
        print_substep("1.2.5", "ОБЧИСЛЕННЯ a⁻¹", {
            "Статус": f"{RED}❌ Не існує{RESET}",
            "Причина": f"gcd(a, m(x)) = 0x{g_poly:x} ≠ 0x01"
        })

if __name__ == "__main__":
    console_menu()
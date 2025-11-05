from flask import Flask, render_template, request,jsonify
from check import *
from crack_time import estimate_crack_times
import json
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle
import string
import re
import secrets
import numpy as np
import time, itertools, string, os
from decimal import Decimal


def safe_default(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError

model_cls = load_model('model_cls.keras')
with open('tokenizer_cls.pkl', 'rb') as f:
    tokenizer_cls = pickle.load(f)
app = Flask(__name__)


@app.route("/")
def display():
    return render_template('index.html')


@app.route("/check", methods=['POST'])
def check_strength(sum=sum):
    if request.method == 'POST':
        password = request.form['pwd']
        switcher = {
            0: "Weak",
            1: "Moderate",
            2: "Strong",
        }
        ans = predictWithLSTM(password)
        print(f"Prediction: {ans} -> {switcher.get(ans, 'Unknown')}")
        api_message = check_password(password)
        issues,suggestions = analyze_password_detailed(password)
        est = estimate_crack_times(password)
        z_display = est['zxcvbn']['crack_times_display'] if est['zxcvbn'] else {}
        brute_gpu = est['brute_force_inferred_charset']['single_gpu']['display']
        brute_cons_gpu = est['brute_force_conservative']['single_gpu']['display']
        return render_template(
            'index.html',
            sum=switcher.get(ans, " "),
            api_message=api_message,
            issues=issues,
            suggestions=suggestions,
            est_display=z_display,
            brute_gpu=brute_gpu,
            brute_cons_gpu=brute_cons_gpu,
            est_raw=json.dumps(est, default=safe_default)
        )

    else:
        return render_template('index.html', sum=" ")
    
DICT_MAX_LINES = 200000      # max lines to check from wordlist
MASK_MAX_COMBINATIONS = 5_000_000  # abort mask if combos exceed this
TIMEOUT_SECONDS = 120        # per-step hard timeout

def try_dictionary_limited(password, wordlist_path='wordlist.txt'):
    start = time.time()
    if not os.path.exists(wordlist_path):
        return {"found": False, "time": 0.0, "tries": 0, "skipped": True}
    tries = 0
    with open(wordlist_path, 'r', errors='ignore') as f:
        for i, line in enumerate(f, 1):
            if i > DICT_MAX_LINES or (time.time() - start) > TIMEOUT_SECONDS:
                break
            candidate = line.rstrip('\n')
            tries += 1
            if candidate == password:
                return {"found": True, "time": time.time() - start, "tries": tries, "skipped": False}
    return {"found": False, "time": time.time() - start, "tries": tries, "skipped": False}

def try_mask_limited(password, mask_pattern):
    start = time.time()
    charmap = {
        'l': string.ascii_lowercase,
        'u': string.ascii_uppercase,
        'd': string.digits,
        's': string.punctuation,
        'a': string.ascii_letters + string.digits + string.punctuation
    }
    
    pools = []
    total_combos_est = 1
    for ch_type, count in mask_pattern:
        pool = charmap.get(ch_type, string.ascii_lowercase)
        for _ in range(count):
            pools.append(pool)
            total_combos_est *= len(pool)
            if total_combos_est > MASK_MAX_COMBINATIONS:
                return {"found": False, "time": 0.0, "tries": 0, "skipped": True, "reason": "mask too large"}

    tries = 0
    for combo in itertools.product(*pools):
        if (time.time() - start) > TIMEOUT_SECONDS:
            break
        tries += 1
        if ''.join(combo) == password:
            return {"found": True, "time": time.time() - start, "tries": tries, "skipped": False}
    return {"found": False, "time": time.time() - start, "tries": tries, "skipped": False}



@app.route('/simulate_crack', methods=['POST'])
def simulate_crack():
    data = request.get_json() or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "password required"}), 400

    # dictionary attempt
    dict_result = try_dictionary_limited(password, wordlist_path='rockyou.txt')

    # mask attempt (demo pattern: 3 lower + 2 digits)
    mask_pattern = data.get("mask_pattern", [('l', 3), ('d', 2)])
    mask_result = try_mask_limited(password, mask_pattern)

   
    # Combine and return
    out = {
        "dictionary": dict_result,
        "mask": mask_result,
        "notes": [
            f"Per-step timeout: {TIMEOUT_SECONDS}s",
            "Workload limits applied to keep demo safe. Increase limits locally if you want longer runs."
        ]
    }
    if request.is_json:
        return jsonify(out)
    else:
        return render_template('index.html', simulate_result=out)


@app.route("/generate", methods=['POST'])
def generate():
    generated_password = generate_secure_password()
    return render_template('index.html', 
                         generated_password=generated_password)

def predictWithLSTM(password):
    common_words = [
    'password', 'admin', 'user', 'login', 'welcome', 'letmein', 'qwerty', 'iloveyou',
    'monkey', 'dragon', 'football', 'baseball', 'princess', 'abc123', '111111',
    '12345', '123456', '12345678', '123456789', '000000', 'passw0rd', 'access',
    'superuser', 'root', 'guest', 'test', 'default', 'changeme'
]
    for word in common_words:
        if password.lower() in word:
            return 0
    password_seq = tokenizer_cls.texts_to_sequences([password])
    password_pad = pad_sequences(password_seq,maxlen=20)

    pred = model_cls.predict(password_pad)
    print(f"Raw predictions: {pred}")
    strength = np.argmax(pred,axis=1)[0]

    return strength

@app.route("/analyze", methods=["POST"])
def analyze_password():
    data = request.get_json()
    password = data.get("password", "")
    if not password:
        return {"strength": "Enter password"}, 400

   
    label = predictWithLSTM(password)

    levels = {0: "Weak", 1: "Moderate", 2: "Strong"}
    return {"strength": levels[label]}

def analyze_password_detailed(password):
    
    issues = []
    suggestions = []
    score = 100
    
    # Length checks
    if len(password) < 8:
        issues.append("Password is too short (minimum 8 characters)")
        suggestions.append("Add more characters")
        score -= 30
    elif len(password) < 12:
        suggestions.append("Consider using 12+ characters for better security")
        score -= 10
    
    # Character diversity
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    if not has_upper:
        issues.append("No uppercase letters")
        suggestions.append("Add uppercase letters (A-Z)")
        score -= 15
    if not has_lower:
        issues.append("No lowercase letters")
        suggestions.append("Add lowercase letters (a-z)")
        score -= 15
    if not has_digit:
        issues.append("No numbers")
        suggestions.append("Add numbers (0-9)")
        score -= 15
    if not has_special:
        issues.append("No special characters")
        suggestions.append("Add special characters (!@#$%^&*)")
        score -= 15
    
    # Pattern detection
    if re.search(r'(.)\1{2,}', password):
        issues.append("Contains repeated characters (e.g., 'aaa', '111')")
        suggestions.append("Avoid repeating characters")
        score -= 20
    
   
    if re.search(r'(?:012|123|234|345|456|567|678|789|890|'
             r'abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|'
             r'cba|dcba|fed|gfe|hgf|ihg|jih|kji|lkj|mlk|nml|onm|pon|qpo|rqp|srq|tsr|uts|vut|wvu|xwv|yxw|zyx)', password.lower()):
        issues.append("Contains sequential patterns (e.g., '123', 'abc', 'xyz')")
        suggestions.append("Avoid sequences like '123' or 'abc'")
        score -= 20
    
    # Common words check
    common_words = [
    'password', 'admin', 'user', 'login', 'welcome', 'letmein', 'qwerty', 'iloveyou',
    'monkey', 'dragon', 'football', 'baseball', 'princess', 'abc123', '111111',
    '12345', '123456', '12345678', '123456789', '000000', 'passw0rd', 'access',
    'superuser', 'root', 'guest', 'test', 'default', 'changeme'
]
    for word in common_words:
        if word in password.lower():
            issues.append(f"Contains common word: '{word}'")
            suggestions.append("Avoid common words")
            score -= 25
            break
    
    # Keyboard patterns
    keyboard_patterns = [
    'qwerty', 'asdfgh', 'zxcvbn', '1qaz', '2wsx', '3edc',
    'qaz', 'wsx', 'edc', 'rfv', 'tgb', 'yhn', 'ujm',
    'qwert', 'werty', 'yuiop', 'poiuy', 'lkjhg', 'mnbvc',
    'qwe', 'rty', 'uio', 'opa', 'sdf', 'dfg', 'fgh', 'ghj',
    'ytrewq', 'plmokn', 'qazwsx', 'wsxedc', 'edcrfv'
]

    for pattern in keyboard_patterns:
        if pattern in password.lower():
            issues.append("Contains keyboard pattern")
            suggestions.append("Avoid keyboard patterns like 'qwerty'")
            score -= 20
            break
    
    score = max(0, score)
    
    return issues,suggestions
    



def generate_secure_password(length=16):
    
    alphabet = string.ascii_letters + string.digits + string.punctuation
    
    # Ensure at least one of each type
    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(string.punctuation)
    ]
    
    
    password += [secrets.choice(alphabet) for _ in range(length - 4)]
    
    
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)
if __name__ == '__main__':
    app.run(debug=True, port=8000)

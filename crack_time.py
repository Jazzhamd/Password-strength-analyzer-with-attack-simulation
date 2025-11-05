import math
import string
from zxcvbn import zxcvbn

# conservative attacker speeds (guesses per second)
ATTACKER_SPEEDS = {
    "human": 1,                  
    "single_cpu": 1e6,          
    "single_gpu": 1e9,           
    "large_gpu_farm": 1e11,      
    "massive_botnet": 1e12       
}

PRINTABLE_CHARSET_SIZE = 95  


def get_charset_size_from_password(password: str) -> int:
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(c in string.punctuation for c in password):
        charset += len(string.punctuation)
    if any(c.isspace() for c in password):
        charset += 1
    return max(1, charset)

def time_to_crack_seconds_from_combinations(total_combos: float, guesses_per_second: float) -> float:
    return (total_combos / 2.0) / guesses_per_second

def combinations_for_password(password: str, use_password_charset=True):
    if use_password_charset:
        charset = get_charset_size_from_password(password)
    else:
        charset = PRINTABLE_CHARSET_SIZE
    length = len(password)
    return charset ** length

def human_readable_time(seconds: float) -> str:
    if seconds < 1:
        return "less than a second"
    intervals = [
        ("years", 60 * 60 * 24 * 365),
        ("days", 60 * 60 * 24),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1)
    ]
    parts = []
    for name, secs in intervals:
        if seconds >= secs:
            val = seconds / secs
            return f"{val:.2f} {name}"
    return "less than a second"

#zxcvbn based attacker-aware estimate
def zxcvbn_estimate(password: str):
    
    try:
        res = zxcvbn(password)
        
        out = {
            "guesses": res.get("guesses"),
            "score": res.get("score"),  
            "crack_times_seconds": res.get("crack_times_seconds", {}),
            "crack_times_display": res.get("crack_times_display", {}),
            "sequence": res.get("sequence", [])
        }
        return out
    except Exception as e:
        
        return None
    

def estimate_crack_times(password: str, show_modes=True):
    result = {}
    # attacker-aware via zxcvbn
    zres = zxcvbn_estimate(password)
    result["zxcvbn"] = zres

    # brute-force using password-inferred charset
    combos = combinations_for_password(password, use_password_charset=True)
    result["brute_force_inferred_charset"] = {}
    for label, speed in ATTACKER_SPEEDS.items():
        secs = time_to_crack_seconds_from_combinations(combos, speed)
        result["brute_force_inferred_charset"][label] = {
            "seconds": secs,
            "display": human_readable_time(secs),
            "guesses": combos
        }

    # conservative brute-force using full printable charset
    combos_conservative = combinations_for_password(password, use_password_charset=False)
    result["brute_force_conservative"] = {}
    for label, speed in ATTACKER_SPEEDS.items():
        secs = time_to_crack_seconds_from_combinations(combos_conservative, speed)
        result["brute_force_conservative"][label] = {
            "seconds": secs,
            "display": human_readable_time(secs),
            "guesses": combos_conservative
        }

    return result
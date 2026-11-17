
import re
import math
import hashlib
import urllib.request
import urllib.error
import getpass

COMMON_PASSWORDS = {
    "password", "password123", "123456",
    "123456789", "qwerty", "admin",
    "letmein", "welcome", "iloveyou"
}


def calculate_entropy(password):
    pool = 0

    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 33

    if pool == 0:
        return 0

    return len(password) * math.log2(pool)


def check_policy(password):
    return {
        "Minimum 8 characters": len(password) >= 8,
        "Uppercase letter": bool(re.search(r"[A-Z]", password)),
        "Lowercase letter": bool(re.search(r"[a-z]", password)),
        "Digit": bool(re.search(r"[0-9]", password)),
        "Special character": bool(
            re.search(r"[^a-zA-Z0-9]", password)
        )
    }


def check_dictionary(password):
    return password.lower() in COMMON_PASSWORDS


def check_breach(password):
    sha1_hash = hashlib.sha1(
        password.encode("utf-8")
    ).hexdigest().upper()

    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = "https://api.pwnedpasswords.com/range/" + prefix

    request = urllib.request.Request(
        url,
        headers={"Add-Padding": "true"}
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            results = response.read().decode("utf-8")

        for line in results.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return int(count)

        return 0

    except (urllib.error.URLError, TimeoutError, ValueError):
        return None


def classify_strength(entropy, breached, common):
    if breached is None:
        return "UNVERIFIED - BREACH CHECK UNAVAILABLE"

    if breached > 0 or common:
        return "Weak"

    if entropy < 28:
        return "Weak"
    elif entropy < 50:
        return "Moderate"
    elif entropy < 70:
        return "Strong"
    else:
        return "Exceptional"


def main():
    print("=" * 50)
    print("       PASSWORD STRENGTH CHECKER")
    print("=" * 50)

    password = getpass.getpass(
        "\nEnter password to evaluate: "
    )

    if not password:
        print("Password cannot be empty.")
        return

    entropy = calculate_entropy(password)
    checks = check_policy(password)
    common = check_dictionary(password)
    breached = check_breach(password)

    strength = classify_strength(
        entropy, breached, common
    )

    print("\n========== SECURITY REPORT ==========")
    print("Password Length:", len(password))
    print(f"Estimated Entropy: {entropy:.2f} bits")

    print("\nPolicy Compliance:")

    for requirement, passed in checks.items():
        status = "PASS" if passed else "FAIL"
        print(f"{requirement}: {status}")

    print("\nDictionary Check:",
          "FOUND" if common else "NOT FOUND")

    if breached is None:
        print("Breach Check: UNAVAILABLE")
    elif breached > 0:
        print(f"Breach Check: FOUND ({breached} occurrences)")
    else:
        print("Breach Check: NOT FOUND")

    print("\nPassword Strength:", strength)

    print("\nRecommendations:")

    if len(password) < 12:
        print("- Increase password length to at least 12 characters.")

    for requirement, passed in checks.items():
        if not passed:
            print(f"- Add requirement: {requirement}")

    if common or (breached is not None and breached > 0):
        print("- Choose a completely different password.")

    if entropy < 50:
        print("- Use a longer, randomly generated password.")

    if breached is None:
        print("- Retry the breach check when internet is available.")

    print("\n======================================")
    print("       ANALYSIS COMPLETED")
    print("======================================")


if __name__ == "__main__":
    main()

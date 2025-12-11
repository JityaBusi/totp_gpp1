from totp_generator import generate_totp_code, verify_totp_code

# 1. Load your seed
with open("data/seed.txt", "r") as f:
    hex_seed = f.read().strip()

# 2. Generate TOTP
code = generate_totp_code(hex_seed)
print("Generated TOTP code:", code)

# 3. Verify the same code
is_valid = verify_totp_code(hex_seed, code)
print("Verification result:", is_valid)

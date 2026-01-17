#!/usr/bin/env python3
from app.totp_generator import generate_totp_code

hex_seed = "1e965bc405d92800fe290ee9a992d479d7f6340e1133dbc5a18ed5eacac2de12"

code, remaining = generate_totp_code(hex_seed)
with open("/cron/totp_output.log", "a") as f:
    f.write(f"{code} ({remaining}s remaining)\n")

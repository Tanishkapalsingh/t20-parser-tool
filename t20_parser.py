import re

FIELDS = [
    ("Version", "4H"),
    ("Security Type", "1A"),
    ("Length", "4H"),
    ("From ID", "4H"),
    ("Connection ID", "2H"),
    ("To ID", "4H"),
    ("Date", "14A"),
    ("Sequence ID", "4H"),
    ("Action Type", "1A"),
    ("Action Priority", "1A"),
    ("Priority Reassignment", "1A"),
    ("Main Key", "8H"),
    ("Action Code", "1A"),
    ("Card ID", "12A"),
    ("Region Key", "8A"),
    ("Report-back Availability", "1A"),
    ("Requested report-back day of month", "2H"),
    ("Backward tolerance", "2H"),
    ("Forward tolerance", "2H"),
    ("Currency", "4H"),
    ("Population ID", "4H"),
    ("STB ID", "12A"),
    ("Signature", "16H"),
]

def parse_t20_command(cmd):
    total_length = sum(int(re.match(r"(\d+)", typ).group(1)) for _, typ in FIELDS)
    if len(cmd) < total_length:
        raise ValueError(f"Command too short. Expected at least {total_length} characters.")

    idx = 0
    result = []
    for name, typ in FIELDS:
        length = int(re.match(r"(\d+)", typ).group(1))
        value = cmd[idx:idx+length]
        result.append((name, typ, value))
        idx += length
    return result

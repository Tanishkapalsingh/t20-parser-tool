import re
from datetime import datetime, timedelta

# ============================= Custom Exception =============================
class T20ParseError(Exception):
    pass

# ============================ Field Definitions =============================
COMMON_FIELDS = [
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
    ("Subscriber ID", "8H"),
]

ACTION_CODE_FIELDS = {
    "q": [
        ("Control", "2H"),
        ("User Number", "1A"),
        ("Pin Control", "1A"),
        ("Pin Number", "4A"),
        ("Parental Rating", "6H"),
        ("Event Speeding Limit", "4H"),
        ("Cumulative Balance", "4H"),
        ("Signature", "16H")
    ],
    "A": [
        ("Continuous Service ID", "4H"),
        ("OPPV Expiration Date", "8A"),
        ("Taping Authorization", "1A"),
        ("Signature", "16H")
    ],
    "X": [
        ("Continuous Service ID", "4H"),
        ("Signature", "16H")
    ],
    "e": [
        ("Logical Channel", "4H"),
        ("Type", "2H"),
        ("Compression Type", "2H"),
        ("Language", "2H"),
        ("STB Deletion Date", "8A"),
        ("EMMG Deletion Date", "8A"),
        ("Total length of text", "2H"),
        ("Number of text fields", "2H"),
        ("Length of text field 1", "2H"),
        ("Unicode & Position", "4H")
    ],
    "O": [
        ("OSD Control", "1A"),
        ("Duration of display", "2H"),
        ("Priority", "1A"),
        ("Compression Type", "2H"),
        ("OSD Number", "2H"),
        ("Length of OSD", "4H"),
        ("Language", "2H"),
        ("Field1", "2H"),
        ("Message", "14H"),
        ("Signature", "16H")
    ],
    "C": [
        ("Card ID", "12A"),
        ("Region Key", "8A"),
        ("Report-back Availability", "1A"),
        ("Requested report-back day of month", "2H"),
        ("Backward tolerance", "2H"),
        ("Forward tolerance", "2H"),
        ("Currency", "4H"),
        ("Population ID", "4H"),
        ("STB ID", "12A"),
        ("Signature", "16H")
    ],
    "j0": [("Signature", "16H")],
    "V": [("Signature", "16H")],
    "j1": [("Signature", "16H")],
    "D": [
        ("Starting Account Balance", "4H"),
        ("Balance Date (MJD)", "4H"),
        ("Day Rental Charge", "4H"),
        ("Previous Recharge Date (MJD)", "4H"),
        ("Previous Recharge Amount", "4H"),
        ("Expected Recharge Date (MJD)", "4H"),
        ("Expected Recharge Amount", "4H"),
        ("Signature", "16H")
    ],
    "B": [],
    "n": [],
    "Q": [],
    "Yn": [],
    "a": [("Signature", "16H")],
    "y": [],
    "Y": [],
    "J": []
}

ACTION_CODE_DESCRIPTIONS = {
    "q": "q (Set User Parameters)",
    "A": "A (Authorize Service) / (Low Balance OSD Bit Unset)",
    "O": "O (OSD Service)",
    "X": "X (Cancel Service)",
    "e": "e (B-Mail)",
    "C": "C (Create Subscriber)",
    "j0": "j0 (Suspension)",
    "j1": "j1 (Resumption)",
    "D": "D (Account Balance Info / Language Change)",
    "B": "B (Multiple Authorization)",
    "V": "Heavy Refresh [Resend All Packet]",
    "n": "n (RTN + Customer ID)",
    "Q": "Q (Reportback Parameters)",
    "a": "Re-Authorize All Services",
    "Yn": "State Bit Set/Unset",
    "y": "Set Region Key",
    "Y": "Set Geographic Region Bytes",
    "J": "Authorize Service/OPPV by Name"
}

Q_AVAIL_MAP = {
    "D": "Day (05:00–23:00 local time)",
    "E": "Evening (23:00–05:00 local time)",
    "A": "Anytime (00:00–23:59 local time)",
    "N": "None",
}

# ====================== Validation / Interpretation Helpers ==================
HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")
ALNUM_RE = re.compile(r"^[0-9A-Za-z]+$")
DIGITS_RE = re.compile(r"^[0-9]+$")

def hex_to_int(hex_str):
    return int(hex_str, 16)

def mjd_to_date(mjd_hex):
    try:
        if not HEX_RE.match(mjd_hex or ""):
            return "Invalid Date"
        mjd = int(mjd_hex, 16)
        mjd_epoch = datetime(1858, 11, 17)
        date = mjd_epoch + timedelta(days=mjd)
        return date.strftime("%d/%m/%Y")
    except:
        return "Invalid Date"

def interpret_field(name, value):
    if "Balance" in name or "Amount" in name or "Charge" in name:
        try:
            interpreted = f"₹{hex_to_int(value) / 100:.2f}"
            return f"{value} → {interpreted}"
        except:
            return value
    elif name == "Date" and len(value) == 14 and DIGITS_RE.match(value or ""):
        try:
            dt = datetime.strptime(value, "%Y%m%d%H%M%S")
            interpreted = dt.strftime("%d/%m/%Y %H:%M:%S")
            return f"{value} → {interpreted}"
        except:
            return value
    elif "Date" in name:
        interpreted = mjd_to_date(value)
        return f"{value} → {interpreted}"
    else:
        return value

def hex_to_ascii(hex_str):
    try:
        if not HEX_RE.match(hex_str or ""):
            return hex_str
        bytes_obj = bytes.fromhex(hex_str)
        return bytes_obj.decode('ascii', errors='ignore').strip()
    except:
        return hex_str

def parse_type(typ):
    m = re.match(r"^(\d+)([A-Za-z])$", typ)
    if not m:
        raise T20ParseError(f"Internal format error: {typ}")
    return int(m.group(1)), m.group(2).upper()

def validate_value_by_type(value, typ, field_name, start_idx):
    length, kind = parse_type(typ)
    if len(value) != length:
        raise T20ParseError(
            f"'{field_name}' is incomplete at index {start_idx}. Expected {length} characters, got {len(value)}. "
            f"Only {max(0, len(value))} were provided for this field."
        )
    if kind == "H":
        if not HEX_RE.match(value):
            raise T20ParseError(
                f"'{field_name}' expects HEX characters at index {start_idx}-{start_idx+length-1} (got '{value}')."
            )
    elif kind == "A":
        if not ALNUM_RE.match(value):
            raise T20ParseError(
                f"'{field_name}' expects alphanumeric ASCII at index {start_idx}-{start_idx+length-1} (got '{value}')."
            )
    else:
        if not ALNUM_RE.match(value):
            raise T20ParseError(
                f"'{field_name}' invalid characters at index {start_idx}-{start_idx+length-1} (got '{value}')."
            )
    return True

def match_action_code(cmd, idx):
    for code in sorted(ACTION_CODE_FIELDS, key=len, reverse=True):
        if cmd[idx:idx + len(code)] == code:
            return code, idx + len(code)
    return None, idx

def min_common_length():
    total = 0
    for _, typ in COMMON_FIELDS:
        l, _ = parse_type(typ)
        total += l
    return total

def validate_command_envelope(cmd):
    if not cmd or not cmd.strip():
        raise T20ParseError("You have entered an invalid command, please enter correct command (empty input).")
    if not ALNUM_RE.match(cmd):
        raise T20ParseError("You have entered an invalid command, please enter correct command (non-alphanumeric characters found).")
    if len(cmd) < (min_common_length() + 1 + 16):
        raise T20ParseError(
            "You have entered an invalid command, please enter correct command (command too short to contain fields + 16-char signature)."
        )

def raise_incomplete_due_to_signature(field_name, expected_len, idx, cmd_len):
    available_before_sig = max(0, (cmd_len - 16) - idx)
    raise T20ParseError(
        f"'{field_name}' field is incomplete at index {idx}. Expected {expected_len} characters, "
        f"but only {available_before_sig} available before the reserved 16-char Signature. "
        f"This usually means the Signature at the end is short or missing (must be 16 HEX characters)."
    )

LANG_CODE_MAP = {
    "tam": "Tamil",
    "tel": "Telugu",
    "ben": "Bengali",
    "kan": "Kannada",
    "hin": "Hindi",
    "eng": "English",
    "mar": "Marathi",
}

# ============================= Main Parser Logic ============================
def parse_t20_command(cmd):
    cmd = (cmd or "").strip()
    validate_command_envelope(cmd)

    if len(cmd) < 16:
        raise T20ParseError("You have entered an invalid command, please enter correct command (missing signature).")
    signature_tail = cmd[-16:]
    if not HEX_RE.match(signature_tail):
        raise T20ParseError(
            "You have entered an invalid command, please enter correct command (Signature must be the last 16 HEX characters)."
        )
    body = cmd[:-16]
    idx = 0
    result = []

    for name, typ in COMMON_FIELDS:
        length, _ = parse_type(typ)
        if idx + length > len(body):
            available_before_sig = max(0, len(body) - idx)
            raise T20ParseError(
                f"You have entered an invalid command, please enter correct command ('{name}' field is incomplete at index {idx}). "
                f"Expected {length} characters, but only {available_before_sig} available before the reserved 16-char Signature. "
                f"This usually means the Signature at the end is short or missing (must be 16 HEX characters)."
            )
        value = body[idx:idx + length]
        validate_value_by_type(value, typ, name, idx)
        interpreted = interpret_field(name, value)
        result.append((name, typ, interpreted))
        idx += length

    action_code, after_code_idx = match_action_code(body, idx)
    if not action_code:
        raise T20ParseError("You have entered an invalid command, please enter correct command (unknown or missing action code).")
    if after_code_idx > len(body):
        raise T20ParseError(
            "You have entered an invalid command, please enter correct command (action code overflowed into signature)."
        )
    result.append(("Action Code", f"{len(action_code)}A", action_code))
    description = ACTION_CODE_DESCRIPTIONS.get(action_code, f"{action_code} (Unknown Action)")
    result.append(("Subscriber Action", "Derived", description))
    idx = after_code_idx

    action_fields = ACTION_CODE_FIELDS.get(action_code, [])

    if action_code == "e":
        for name, typ in action_fields:
            if name == "Signature":
                break
            length, _ = parse_type(typ)
            if idx + length > len(body):
                raise_incomplete_due_to_signature(name, length, idx, len(cmd))
            value = body[idx:idx + length]
            validate_value_by_type(value, typ, name, idx)
            result.append((name, typ, value))
            idx += length
        filler_text = body[idx:]
        result.append(("Filler text", "H/vary", filler_text))
        result.append(("Signature", "16H", signature_tail))
        return result

    elif action_code == "O":
        for name, typ in action_fields:
            if name == "Message":
                msg_end_idx = len(body)
                if idx > msg_end_idx:
                    available_before_sig = max(0, msg_end_idx - idx)
                    raise T20ParseError(
                        f"OSD 'Message' segment cannot start at index {idx}: only {available_before_sig} chars left "
                        f"before the reserved 16-char Signature. The Signature at the end may be short or missing "
                        f"(must be 16 HEX characters)."
                    )
                value = body[idx:msg_end_idx]
                interpreted_msg = hex_to_ascii(value)
                result.append((name, f"{len(value)}H", f"{value} → {interpreted_msg}" if interpreted_msg != value else value))
                idx = msg_end_idx
            elif name == "Signature":
                continue
            else:
                length, _ = parse_type(typ)
                if idx + length > len(body):
                    raise_incomplete_due_to_signature(name, length, idx, len(cmd))
                value = body[idx:idx + length]
                validate_value_by_type(value, typ, name, idx)
                interpreted = interpret_field(name, value)
                result.append((name, typ, interpreted))
                idx += length
        result.append(("Signature", "16H", signature_tail))
        return result

    elif action_code == "Yn":
        yn_pattern = re.compile(r'(Yn)([AD])([0-9A-Fa-f]{3})')
        yn_matches = yn_pattern.findall(body[idx:])
        if not yn_matches:
            raise T20ParseError("No valid Yn blocks found after action code 'Yn'.")
        for i, (action, bit, region_hex) in enumerate(yn_matches, 1):
            try:
                region_dec = int(region_hex, 16)
            except:
                region_dec = f"Invalid HEX ({region_hex})"
            result.append((f"Action Code {i}" ,"2A", action))
            result.append((f"Yn Set/Unset Action {i}", "1A", bit + (" (Set)" if bit=="A" else " (Unset)")))
            result.append((f"Region {i}", "3H", f"{region_hex} → {region_dec}"))
        result.append(("Signature", "16H", signature_tail))
        return result

    elif action_code == "Q":
        length = 8
        if idx + length > len(body):
            raise_incomplete_due_to_signature("Region Key", length, idx, len(cmd))
        region_key = body[idx:idx+length]
        validate_value_by_type(region_key, "8A", "Region Key", idx)
        result.append(("Region Key", "8A", region_key))
        idx += length

        length = 1
        if idx + length > len(body):
            raise_incomplete_due_to_signature("Reportback Availability", length, idx, len(cmd))
        avail = body[idx:idx+length]
        validate_value_by_type(avail, "1A", "Reportback Availability", idx)
        result.append(("Reportback Availability", "1A", f"{avail} → {Q_AVAIL_MAP.get(avail, 'Unknown')}"))
        idx += length

        hex_fields = [
            ("Requested reportback day of month", "2H"),
            ("Backward tolerance for reportback day (in days)", "2H"),
            ("Forward tolerance for reportback day (in days)", "2H"),
            ("Currency", "4H"),
            ("Population ID", "4H"),
            ("SMS Subscriber ID", "8H"),
        ]
        for name, typ in hex_fields:
            l, _ = parse_type(typ)
            if idx + l > len(body):
                raise_incomplete_due_to_signature(name, l, idx, len(cmd))
            raw = body[idx:idx+l]
            validate_value_by_type(raw, typ, name, idx)
            try:
                val_dec = int(raw, 16)
                interpreted = f"{raw} → {val_dec}"
            except Exception:
                interpreted = raw
            result.append((name, typ, interpreted))
            idx += l

        remaining = len(body) - idx
        if remaining >= 12:
            stb = body[idx:idx+12]
            validate_value_by_type(stb, "12A", "STB ID (optional)", idx)
            result.append(("STB ID (optional)", "12A", stb))
            idx += 12
        elif remaining > 0:
            stb_short = body[idx:]
            validate_value_by_type(stb_short, f"{remaining}A", "STB ID (optional, short)", idx)
            result.append(("STB ID (optional, short)", f"{remaining}A", stb_short))
            idx = len(body)

        result.append(("Signature", "16H", signature_tail))
        return result

    elif action_code == "D":
        lang_change_detected = False
        start_idx = idx
        try:
            if len(body) - start_idx >= 10:
                expiry_raw = body[start_idx:start_idx+8]
                rem_len_hex = body[start_idx+8:start_idx+10]
                if ALNUM_RE.match(expiry_raw or "") and HEX_RE.match(rem_len_hex or ""):
                    remaining_len = int(rem_len_hex, 16)
                    after_len_idx = start_idx + 10
                    remaining_chunk = body[after_len_idx:]
                    if len(remaining_chunk) == remaining_len and remaining_len >= (12 + 2 + 4 + 6):
                        stb_mask = remaining_chunk[:12]
                        marker = remaining_chunk[12:14]
                        named_param = remaining_chunk[14:18]
                        lang_hex = remaining_chunk[18:]
                        if HEX_RE.match(stb_mask or "") and HEX_RE.match(named_param or "") and HEX_RE.match(lang_hex or ""):
                            if marker.upper() == "9B" and len(lang_hex) == 6:
                                lang_change_detected = True
        except Exception:
            lang_change_detected = False

        if lang_change_detected:
            result.append(("Subscriber Action", "Derived", "D (Language Change)"))

            expiry_raw = body[idx:idx+8]; idx += 8
            length_hex = body[idx:idx+2]; idx += 2
            validate_value_by_type(expiry_raw, "8A", "Packet Expiry Date", idx-10)
            validate_value_by_type(length_hex, "2H", "Length of remaining data", idx-2)
            remaining_len = int(length_hex, 16)
            chunk = body[idx:idx+remaining_len]
            if len(chunk) != remaining_len:
                raise_incomplete_due_to_signature("Language Change Data", remaining_len, idx, len(cmd))
            stb_mask = chunk[:12]
            marker = chunk[12:14]
            named_param = chunk[14:18]
            lang_hex = chunk[18:]
            validate_value_by_type(stb_mask, "12H", "STB Filter / IRD Mask", idx)
            validate_value_by_type(marker, "2H", "Language Change Marker", idx+12)
            validate_value_by_type(named_param, "4H", "Named Parameter", idx+14)
            validate_value_by_type(lang_hex, "6H", "Language Code", idx+18)

            try:
                dt = datetime.strptime(expiry_raw, "%Y%m%d")
                expiry_human = dt.strftime("%d/%m/%Y")
                expiry_display = f"{expiry_raw} → {expiry_human}"
            except:
                expiry_display = expiry_raw

            stb_display = f"{stb_mask} → Any IRD" if stb_mask.upper() == "FFFFFFFFFFFF" else stb_mask
            lang_ascii = hex_to_ascii(lang_hex).lower()
            lang_name = LANG_CODE_MAP.get(lang_ascii, f"Unknown ({lang_ascii})" if lang_ascii else "Unknown")

            result.append(("Packet Expiry Date", "8A", expiry_display))
            result.append(("Length of remaining data", "2H", f"{length_hex} → {int(length_hex,16)}"))
            result.append(("STB Filter / IRD Mask", "12H", stb_display))
            result.append(("Language Change Marker", "2H", marker))
            result.append(("Named Parameter", "4H", named_param))
            result.append(("Language Code", "6H", f"{lang_hex} → {lang_ascii}"))
            result.append(("Language (derived)", "Derived", lang_name))
            result.append(("Signature", "16H", signature_tail))
            return result

        result.append(("Subscriber Action", "Derived", "D (Account Balance Info)"))

        fields = [
            ("Expiry of EMM Command", "8A", False),
            ("Value1", "16H", False),
            ("Value2", "2H", False),
            ("Value3", "4H", False),
            ("Starting Account Balance", "8H", "money"),
            ("Account Balance generated by SMS on", "8H", "mjd"),
            ("Day Rental Charge", "8H", "money"),
            ("Date when subscriber recharged previously", "8H", "mjd"),
            ("Amount of previous recharge", "8H", "money"),
            ("Date subscriber expected to recharge", "8H", "mjd"),
            ("Expected amount of next recharge", "8H", "money"),
        ]
        for name, typ, convert in fields:
            length, _ = parse_type(typ)
            if idx + length > len(body):
                raise_incomplete_due_to_signature(name, length, idx, len(cmd))
            value = body[idx:idx+length]
            validate_value_by_type(value, typ, name, idx)
            if convert == "money":
                try:
                    interpreted = f"{value} → ₹{hex_to_int(value) / 100:.2f}"
                except:
                    interpreted = value
            elif convert == "mjd":
                interpreted = f"{value} → {mjd_to_date(value)}"
            else:
                interpreted = value
            result.append((name, typ, interpreted))
            idx += length
        result.append(("Signature", "16H", signature_tail))
        return result

    elif action_code == "n":
        if idx + 8 > len(body):
            raise_incomplete_due_to_signature("Deletion Date", 8, idx, len(cmd))
        deletion_date_raw = body[idx:idx+8]; idx += 8
        validate_value_by_type(deletion_date_raw, "8A", "Deletion Date", idx-8)
        try:
            dt = datetime.strptime(deletion_date_raw, "%Y%m%d")
            deletion_date = f"{deletion_date_raw} → {dt.strftime('%d/%m/%Y')}"
        except:
            deletion_date = deletion_date_raw
        result.append(("Deletion Date", "8A", deletion_date))
        if idx + 2 > len(body):
            raise_incomplete_due_to_signature("Data Length", 2, idx, len(cmd))
        data_len_hex = body[idx:idx+2]; idx += 2
        validate_value_by_type(data_len_hex, "2H", "Data Length", idx-2)
        try: data_len_int = int(data_len_hex, 16)
        except: data_len_int = 0
        result.append(("Data Length", "2H", f"{data_len_hex} → {data_len_int}"))
        
        if idx + 2 > len(body):
            raise_incomplete_due_to_signature("Sub Action Code", 2, idx, len(cmd))
        sub_action = body[idx:idx+2]; idx += 2
        validate_value_by_type(sub_action, "2H", "Sub Action Code", idx-2)
        result.append(("Sub Action Code", "2H", sub_action))
        
        if idx + 2 > len(body):
            raise_incomplete_due_to_signature("Usages Group", 2, idx, len(cmd))
        usages_group = body[idx:idx+2]; idx += 2
        validate_value_by_type(usages_group, "2H", "Usages Group", idx-2)
        result.append(("Usages Group", "2H", usages_group))
        
        if idx + 4 > len(body):
            raise_incomplete_due_to_signature("NP Name", 4, idx, len(cmd))
        np_name = body[idx:idx+4]; idx += 4
        validate_value_by_type(np_name, "4A", "NP Name", idx-4)
        result.append(("NP Name", "4H", np_name))
        
        if idx + 2 > len(body):
            raise_incomplete_due_to_signature("NP Data Length", 2, idx, len(cmd))
        np_data_len_hex = body[idx:idx+2]; idx += 2
        validate_value_by_type(np_data_len_hex, "2H", "NP Data Length", idx-2)
        try: np_data_len = int(np_data_len_hex, 16)
        except: np_data_len = 0
        result.append(("NP Data Length", "2H", f"{np_data_len_hex} → {np_data_len}"))
        
        if idx + np_data_len*2 > len(body):
            raise_incomplete_due_to_signature("NP Data", np_data_len*2, idx, len(cmd))
        np_data_hex = body[idx:idx + (np_data_len*2)]; idx += np_data_len*2
        if not HEX_RE.match(np_data_hex):
            raise T20ParseError(f"NP Data contains invalid HEX characters at index {idx - np_data_len*2}")
        np_data_ascii = hex_to_ascii(np_data_hex)
        
        if "254E" in np_data_hex.upper():
            parts = np_data_hex.upper().split("254E", 1)
            rtn_hex = parts[0] + "254E"
            cust_hex = parts[1]
            if not HEX_RE.match(rtn_hex):
                raise T20ParseError("RTN hex part contains invalid HEX characters")
            if not HEX_RE.match(cust_hex):
                raise T20ParseError("Customer ID hex part contains invalid HEX characters")
            result.append(("RTN Raw", f"{len(rtn_hex)}H", rtn_hex))
            result.append(("RTN Decoded", "ASCII", hex_to_ascii(rtn_hex)))
            result.append(("Customer ID Raw", f"{len(cust_hex)}H", cust_hex))
            result.append(("Customer ID Decoded", "ASCII", hex_to_ascii(cust_hex)))
        else:
            result.append(("NP Data Raw", f"{len(np_data_hex)}H", np_data_hex))
            result.append(("NP Data Decoded", "ASCII", np_data_ascii))
        
        if len(signature_tail) != 16 or not HEX_RE.match(signature_tail):
            raise T20ParseError("Signature is malformed. Must be 16 HEX characters.")
        result.append(("Signature", "16H", signature_tail))
        return result

    elif action_code == "y":
        if idx + 2 > len(body):
            raise_incomplete_due_to_signature("From Region", 2, idx, len(cmd))
        from_region_hex = body[idx:idx+2]; idx += 2
        validate_value_by_type(from_region_hex, "2H", "From Region", idx-2)
        from_region = int(from_region_hex, 16)
        result.append(("From Region", "2H", f"{from_region_hex} → {from_region}"))
 
        if idx + 2 > len(body):
            raise_incomplete_due_to_signature("To Region", 2, idx, len(cmd))
        to_region_hex = body[idx:idx+2]; idx += 2
        validate_value_by_type(to_region_hex, "2H", "To Region", idx-2)
        to_region = int(to_region_hex, 16)
        result.append(("To Region", "2H", f"{to_region_hex} → {to_region}"))
 
        mask_hex = body[idx:]
        if not mask_hex:
            raise T20ParseError("Missing Region Mask for Action Code 'y'.")
        if not HEX_RE.match(mask_hex):
            raise T20ParseError("Region Mask contains invalid characters (must be HEX).")
        mask_decimal = int(mask_hex, 16)
        result.append(("Region Mask", f"{len(mask_hex)}H", f"{mask_hex} → {mask_decimal}"))
        idx = len(body)
 
        result.append(("Signature", "16H", signature_tail))
        return result
 
    elif action_code == "J":
        as_pattern = re.compile(r"As(\d{2})([A-Za-z0-9_-]+?)(\d{8})")
        matches = as_pattern.findall(body[idx:])
        if not matches:
            raise T20ParseError("No valid 'As' service blocks found after action code 'As'.")
 
        for i, (length_str, service, expiry_raw) in enumerate(matches, 1):
            try:
                length = int(length_str)
            except:
                length = None
 
            try:
                expiry_dt = datetime.strptime(expiry_raw, "%Y%m%d")
                expiry_display = f"{expiry_raw} → {expiry_dt.strftime('%d/%m/%Y')}"
            except:
                expiry_display = expiry_raw
 
            result.append((f"Action code {i}", "2A", "As"))
            result.append((f"Length of Service/OPPV name {i}", "2H", length_str if length is None else f"{length_str} → {length}"))
            result.append((f"Service/OPPV name {i}", f"{length}A", service))
            result.append((f"OPPV Expiration date {i}", "8A", expiry_display))
 
        result.append(("Signature", "16H", signature_tail))
        return result

    elif action_code == "Y":
        y_pattern = re.compile(r'(Y)([AD])([0-9A-Fa-f]{2})')
        y_matches = y_pattern.findall(body[idx:])
        if not y_matches:
            raise T20ParseError("No valid Y blocks found after action code 'Y'.")
        for i, (action_code_char, set_clear, area_hex) in enumerate(y_matches, 1):
            try:
                area_dec = int(area_hex, 16)
            except:
                area_dec = f"Invalid HEX ({area_hex})"
            result.append((f"Action Code {i}", "1A", action_code_char))
            result.append((f"Set/Clear {i}", "1A", f"{set_clear} → {'Set' if set_clear=='A' else 'Clear'}"))
            result.append((f"Area {i}", "2H", f"{area_hex} → {area_dec}"))
        result.append(("Signature", "16H", signature_tail))
        return result

    elif action_code == "A":
        fields_A = ACTION_CODE_FIELDS["A"]
        parsed_values = {}
        for name, typ in fields_A:
            if name == "Signature":
                continue
            length, _ = parse_type(typ)
            if idx + length > len(body):
                raise_incomplete_due_to_signature(name, length, idx, len(cmd))
            value = body[idx:idx + length]
            validate_value_by_type(value, typ, name, idx)
            parsed_values[name] = value
            idx += length
        expiry_raw = parsed_values.get("OPPV Expiration Date", "")
        try:
            expiry_dt = datetime.strptime(expiry_raw, "%Y%m%d")
            formatted_expiry = expiry_dt.strftime("%d/%m/%Y")
        except:
            expiry_dt = None
            formatted_expiry = expiry_raw

        action_description = "Authorize Service"
        if expiry_dt:
            now = datetime.now()
            if expiry_dt.year > now.year or (expiry_dt.year == now.year and expiry_dt.month > now.month):
                action_description = "Low Balance OSD Bit Unset"

        for name, typ in fields_A:
            if name == "Signature":
                continue
            value = parsed_values.get(name, "")
            if name == "OPPV Expiration Date":
                interpreted = f"{value} → {formatted_expiry}"
            else:
                interpreted = value
            result.append((name, typ, interpreted))
        result.append(("Derived Action", "Derived", action_description))
        result.append(("Signature", "16H", signature_tail))
        return result

    elif action_code == "B":
        param_info_length = 11
        if idx + param_info_length > len(body):
            raise_incomplete_due_to_signature("Parameter Info", param_info_length, idx, len(cmd))
        param_info = body[idx:idx + param_info_length]
        validate_value_by_type(param_info, "11H", "Parameter Info", idx)
        result.append(("Parameter Info", "11H", param_info))
        idx += param_info_length

        remaining_before_sig = len(body) - idx
        if remaining_before_sig < 0:
            raise T20ParseError(
                "You have entered an invalid command, please enter correct command (no room left before the 16-char Signature)."
            )
        if remaining_before_sig % 14 != 0:
            raise T20ParseError(
                "You have entered an invalid command, please enter correct command "
                "(authorization blocks misaligned: remaining length before Signature is not a multiple of 14). "
                "This often happens when the Signature at the end is short or missing."
            )

        num_blocks = remaining_before_sig // 14
        cas_id_count = 0
        for i in range(num_blocks):
            if idx + 14 > len(body):
                raise_incomplete_due_to_signature("Authorization Block", 14, idx, len(cmd))
            block = body[idx:idx + 14]
            auth_cmd = block[0]
            service_id_hex = block[1:5]
            expiry_date_raw = block[5:13]
            tap_indicator = block[13]

            validate_value_by_type(auth_cmd, "1A", f"Authorization #{i+1} - Authorization", idx)
            validate_value_by_type(service_id_hex, "4H", f"Authorization #{i+1} - CAS ID", idx+1)
            validate_value_by_type(expiry_date_raw, "8H", f"Authorization #{i+1} - Expiry Date", idx+5)
            validate_value_by_type(tap_indicator, "1A", f"Authorization #{i+1} - Tapping", idx+13)

            try:
                cas_id_decimal = str(int(service_id_hex, 16))
            except:
                cas_id_decimal = f"Invalid HEX ({service_id_hex})"

            result.append((f"Authorization #{i+1} - Authorization", "1A", auth_cmd))
            result.append((f"Authorization #{i+1} - CAS ID", "4H", f"{service_id_hex} → {cas_id_decimal}"))
            result.append((f"Authorization #{i+1} - Expiry Date", "8H", expiry_date_raw))
            result.append((f"Authorization #{i+1} - Tapping", "1A", tap_indicator))

            cas_id_count += 1
            idx += 14

        result.append(("Signature", "16H", signature_tail))
        result.append(("Total Number of CAS IDs", "Derived", str(cas_id_count)))
        return result

    else:
        parsed_signature_field = None
        for name, typ in action_fields:
            if name == "Signature":
                parsed_signature_field = ("Signature", typ)
                continue
            length, _ = parse_type(typ)
            if idx + length > len(body):
                raise_incomplete_due_to_signature(name, length, idx, len(cmd))
            value = body[idx:idx + length]
            validate_value_by_type(value, typ, name, idx)
            interpreted = interpret_field(name, value)
            result.append((name, typ, interpreted))
            idx += length

        if parsed_signature_field is not None:
            decl_len, decl_kind = parse_type(parsed_signature_field[1])
            if decl_len != 16 or decl_kind != "H":
                raise T20ParseError(
                    "You have entered an invalid command, please enter correct command (signature format must be 16H)."
                )

        result.append(("Signature", "16H", signature_tail))
        return result

# ================================ CLI Testing ===============================
if __name__ == "__main__":
    user_input = input("Enter T20 command: ").strip()
    try:
        parsed = parse_t20_command(user_input)
        print(f"\n{'Field Name':35} {'Length & Type':15} {'Value'}")
        print("-" * 80)
        for name, typ, value in parsed:
            print(f"{name:35} {typ:15} {value}")
    except T20ParseError as e:
        print("You have entered an invalid command, please enter correct command")
        print("Details:", str(e))
    except Exception as e:
        print("Unexpected error while parsing")
        print("Details:", str(e))

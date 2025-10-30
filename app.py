import streamlit as st
import pandas as pd
import re
from t20_parser import parse_t20_command, T20ParseError
 
st.set_page_config(page_title="T20 Command Parser", layout="centered")
st.markdown("""
<style>
    body { background-color: #A6C0CD; }
    .stApp { background-color: #A6C0CD; }
    .block-container { padding-top: 2rem; padding-bottom: 2rem; }
    .dataframe td[data-changed="true"] { background-color: #FCE4EC !important; }
</style>
""", unsafe_allow_html=True)
 
st.title("📡 T20 Command Parser")
st.markdown("Decode **T20 subscriber action commands** in a user friendly interface.")
 
with st.expander("ℹ️ How to use this tool"):
    st.markdown("""
    - Paste a **T20 command** string below.
    - Click **Parse Command**.
    - The output will include **fixed fields** and **Action Code–based fields**.
    """)
 
def clean_t20_input(s: str) -> str:
    if not s:
        return ""
    s0 = s
    s = re.sub(r'(?is)(?:;*\s*\.*\s*continued\s*\.*\s*;*|continue)', '', s)
    s = re.sub(r'\s+', '', s)
    s = re.sub(r'[^0-9A-Za-z]', '', s)
    return s
 
command = st.text_area(
    "📋 Enter the T20 command string:",
    height=160,
    placeholder="Paste your T20 command here (split parts with 'continue' or ';...continued...;' are ok)..."
)
 
if st.button("🔍 Parse Command"):
    original = command or ""
    command_str = clean_t20_input(original)
 
    if not command_str:
        st.warning("⚠️ Please enter a T20 command before parsing.")
    elif len(command_str) < 10:
        st.error("❌ Invalid command: Too short after cleaning.")
    elif not command_str.isalnum():
        st.error("❌ Invalid command: Contains non-alphanumeric characters after cleaning.")
    else:
        try:
            parsed_data = parse_t20_command(command_str)
 
            # Fields that need Hex → Decimal conversion
            hex_to_decimal_fields = {
                "Length",
                "Duration of Display",
                "Duration of display",
                "Length of OSD",
                "Subscriber ID",
            }
 
            updated_data = []
            for field_name, field_type, field_value in parsed_data:
                if field_name in hex_to_decimal_fields:
                    raw_hex = str(field_value).split("→", 1)[0].strip()
                    try:
                        decimal_value = int(raw_hex, 16)
                        updated_data.append((field_name, field_type, f"{raw_hex} → {decimal_value} (decimal)"))
                    except ValueError:
                        updated_data.append((field_name, field_type, f"{field_value} (invalid hex)"))
                else:
                    updated_data.append((field_name, field_type, field_value))
 
            df = pd.DataFrame(updated_data, columns=["Field Name", "Type", "Value"])
            if len(original) != len(command_str):
                st.info(f"🧹 Cleaned input: removed {len(original) - len(command_str)} non-alphanumeric/continuation characters.")
            st.success("✅ Command parsed successfully.")
            st.dataframe(df, use_container_width=True)
 
        except T20ParseError as e:
            st.error(f"❌ Parsing Error: {str(e)}")
        except Exception as ex:
            st.error(f"❌ Unknown error occurred during parsing: {ex}")
 
st.markdown("---")

import streamlit as st
from t20_parser import parse_t20_command

st.set_page_config(page_title="T20 Command Parser", layout="wide")

st.title("🔍 T20 Command Parser")
st.markdown("Paste a raw T20 command string below and click **Parse** to see the breakdown.")

command_input = st.text_area("Enter T20 Command", height=150)

if st.button("Parse"):
    try:
        parsed = parse_t20_command(command_input.strip())
        st.success("✅ Command Parsed Successfully!")
        
        st.markdown("### 🧾 Parsed Output")
        st.table([{ "Field Name": name, "Type": typ, "Value": val } for name, typ, val in parsed])
    
    except Exception as e:
        st.error(f"❌ Error: {str(e)}")

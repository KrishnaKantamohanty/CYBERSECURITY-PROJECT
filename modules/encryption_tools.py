import streamlit as st
from pathlib import Path
from utils.encryption import encrypt_file, decrypt_file, MAX_FILE_SIZE_BYTES
from utils.security import record_activity
from utils.theme import page_header


def render():
    page_header(
        "File Encryption & Decryption",
        "Protect local files with password-derived keys and authenticated encryption (PBKDF2 + Fernet).",
        "🔑",
    )

    tab1, tab2 = st.tabs(["🔒 Encrypt File", "🔓 Decrypt File"])

    temp_dir = Path("temp")
    temp_dir.mkdir(exist_ok=True)

    with tab1:
        st.subheader("Encrypt a File")
        st.caption("Upload any file, provide a secret encryption password, and generate a downloadable encrypted file.")

        uploaded_enc_file = st.file_uploader("Upload file to encrypt", key="file_encrypt_uploader")
        password_enc = st.text_input("Encryption Password", type="password", key="pwd_encrypt_input")

        if st.button("Encrypt File", key="btn_run_encrypt"):
            if not uploaded_enc_file:
                st.error("Please upload a file to encrypt.")
            elif not password_enc:
                st.error("Please enter an encryption password.")
            elif len(uploaded_enc_file.getvalue()) > MAX_FILE_SIZE_BYTES:
                st.error(f"File exceeds maximum allowed size of {MAX_FILE_SIZE_BYTES // (1024*1024)} MB.")
            else:
                source_path = temp_dir / uploaded_enc_file.name
                source_path.write_bytes(uploaded_enc_file.getvalue())

                output_name = uploaded_enc_file.name + ".encrypted"
                output_path = temp_dir / output_name

                try:
                    encrypt_file(source_path, output_path, password_enc)
                    record_activity(f"File encrypted: {uploaded_enc_file.name}", "file")

                    st.success("✅ **Encryption Successful!**")
                    st.markdown(
                        f"""
                        <div class="result-card">
                            <h4>Encrypted File Details</h4>
                            <p><strong>Original File:</strong> {uploaded_enc_file.name}</p>
                            <p><strong>Output File:</strong> {output_name}</p>
                            <p><strong>Encryption Algorithm:</strong> PBKDF2-HMAC-SHA256 (260k iterations) + AES-128-CBC / HMAC-SHA256 (Fernet)</p>
                            <p><strong>Salt:</strong> 16-byte random salt generated</p>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    with open(output_path, "rb") as f:
                        st.download_button(
                            label=f"📥 Download {output_name}",
                            data=f.read(),
                            file_name=output_name,
                            mime="application/octet-stream",
                            key="btn_download_enc",
                        )
                except Exception as exc:
                    st.error(f"Encryption failed: {exc}")

    with tab2:
        st.subheader("Decrypt a File")
        st.caption("Upload a `.encrypted` file and enter the correct password to restore the original file.")

        uploaded_dec_file = st.file_uploader("Upload encrypted file (.encrypted)", key="file_decrypt_uploader")
        password_dec = st.text_input("Decryption Password", type="password", key="pwd_decrypt_input")

        if st.button("Decrypt File", key="btn_run_decrypt"):
            if not uploaded_dec_file:
                st.error("Please upload an encrypted file.")
            elif not password_dec:
                st.error("Please enter the decryption password.")
            else:
                source_path = temp_dir / uploaded_dec_file.name
                source_path.write_bytes(uploaded_dec_file.getvalue())

                orig_name = uploaded_dec_file.name
                if orig_name.endswith(".encrypted"):
                    output_name = orig_name[:-10]
                else:
                    output_name = "decrypted_" + orig_name

                output_path = temp_dir / output_name

                try:
                    decrypt_file(source_path, output_path, password_dec)
                    record_activity(f"File decrypted: {output_name}", "file")

                    st.success("✅ **Decryption Successful!**")
                    st.markdown(
                        f"""
                        <div class="result-card">
                            <h4>Decrypted File Details</h4>
                            <p><strong>Encrypted File:</strong> {uploaded_dec_file.name}</p>
                            <p><strong>Restored File:</strong> {output_name}</p>
                            <p><strong>Verification:</strong> Authentication tag and password verified successfully.</p>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    with open(output_path, "rb") as f:
                        st.download_button(
                            label=f"📥 Download {output_name}",
                            data=f.read(),
                            file_name=output_name,
                            mime="application/octet-stream",
                            key="btn_download_dec",
                        )
                except Exception as exc:
                    st.error(str(exc))


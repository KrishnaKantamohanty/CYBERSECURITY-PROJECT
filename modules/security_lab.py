import hashlib
import streamlit as st
from utils.theme import page_header
from utils.security import check_password_strength, generate_password
from utils.hashing import hash_password, verify_password
from utils.encryption import encrypt_bytes, decrypt_bytes


def render():
    page_header(
        "Interactive Security Lab",
        "Safe local educational demonstrations explaining fundamental cybersecurity concepts.",
        "🧪",
    )

    st.warning("⚠️ **Educational Scope**: All lab demonstrations run strictly locally in volatile memory. No malicious, offensive, or network attack tools are provided.")

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🔐 Passwords",
        "🔒 Cryptography & Cipher",
        "👤 Auth & 2FA",
        "🌐 Phishing & URL Heuristics",
        "📁 Hash Mismatch Demo",
    ])

    # -------------------------------------------------------------------------
    # TAB 1: Password Security
    # -------------------------------------------------------------------------
    with tab1:
        st.subheader("Weak vs Strong Password Comparison")
        st.write("Compare how password complexity impacts brute-force resistance and entropy:")

        c1, c2 = st.columns(2)
        with c1:
            st.markdown("#### Weak Example (`password123`)")
            res_weak = check_password_strength("password123")
            st.error(f"Score: {res_weak['score']}/100 | Rating: {res_weak['rating']}")
            st.write("Warnings:", res_weak["warnings"])

        with c2:
            st.markdown("#### Strong Example (Generated)")
            strong_sample = generate_password(16, True, True, True, True)
            res_strong = check_password_strength(strong_sample)
            st.success(f"Score: {res_strong['score']}/100 | Rating: {res_strong['rating']}")
            st.code(strong_sample)

    # -------------------------------------------------------------------------
    # TAB 2: Cryptography & Caesar Cipher
    # -------------------------------------------------------------------------
    with tab2:
        st.subheader("Hashing vs Encryption & Caesar Cipher")

        st.markdown(
            """
            - **Hashing**: One-way mathematical transformation (e.g. SHA-256, bcrypt). *Cannot be decrypted*.
            - **Encryption**: Two-way reversible transformation using a secret key (e.g. AES-128, Fernet). *Can be decrypted with password*.
            """
        )

        st.markdown("---")
        st.subheader("Caesar Cipher Demonstration")
        st.caption("A classic substitution cipher where letters in the plaintext are shifted by a fixed position down the alphabet.")

        plaintext = st.text_input("Plaintext Message", value="DEFEND THE CASTLE AT DAWN", key="lab_caesar_input")
        shift = st.slider("Alphabet Shift Key", 1, 25, 3, key="lab_caesar_shift")

        def caesar_cipher(text: str, k: int, mode: str = "encrypt") -> str:
            if mode == "decrypt":
                k = -k
            res = []
            for char in text:
                if char.isalpha():
                    base = ord('A') if char.isupper() else ord('a')
                    res.append(chr((ord(char) - base + k) % 26 + base))
                else:
                    res.append(char)
            return "".join(res)

        ciphertext = caesar_cipher(plaintext, shift, "encrypt")
        decrypted_text = caesar_cipher(ciphertext, shift, "decrypt")

        c1, c2 = st.columns(2)
        with c1:
            st.markdown(f"**Encrypted Ciphertext (Shift +{shift}):**")
            st.code(ciphertext)
        with c2:
            st.markdown(f"**Decrypted Plaintext (Shift -{shift}):**")
            st.code(decrypted_text)

    # -------------------------------------------------------------------------
    # TAB 3: Auth & 2FA Concepts
    # -------------------------------------------------------------------------
    with tab3:
        st.subheader("Authentication & Bcrypt Salting")
        st.write("Demonstration of bcrypt salted password hashing:")

        sample_pwd = st.text_input("Enter sample password to hash with bcrypt", value="SecurityLab2026!", type="password", key="lab_pwd_hash_input")
        if st.button("Generate Bcrypt Hash", key="btn_lab_bcrypt"):
            h1 = hash_password(sample_pwd)
            h2 = hash_password(sample_pwd)

            st.write("**Bcrypt Hash Output #1:**", h1.decode())
            st.write("**Bcrypt Hash Output #2:**", h2.decode())
            st.info("💡 **Notice**: The two bcrypt hashes above are different even for the EXACT same input password! This is because bcrypt automatically generates a unique random **salt** for every hash operation to prevent rainbow table attacks.")

    # -------------------------------------------------------------------------
    # TAB 4: Phishing Heuristics
    # -------------------------------------------------------------------------
    with tab4:
        st.subheader("Deceptive Phishing URL Indicators")
        st.write("Select a sample suspicious URL below to view heuristic red flags:")

        sample_url = st.selectbox(
            "Select Sample URL",
            [
                "http://login.paypal.verify-account.sec-update.info/login.php",
                "http://192.168.1.1/admin-login-secure",
                "https://secure-bank-login--verification.com@malicious-site.net/auth",
                "https://accounts.google.com/ServiceLogin",
            ]
        )

        if sample_url.startswith("http://login.paypal"):
            st.error("🚨 Red Flags: Excessive subdomains, deceptive brand domain spoofing, HTTP unencrypted.")
        elif "192.168" in sample_url:
            st.warning("⚠️ Red Flags: Raw IP address used as hostname, HTTP unencrypted.")
        elif "@" in sample_url:
            st.error("🚨 Red Flags: Embedded `@` credential character, misleading prefix host.")
        else:
            st.success("✅ Clean URL structure from legitimate domain.")

    # -------------------------------------------------------------------------
    # TAB 5: Hash Mismatch Demo
    # -------------------------------------------------------------------------
    with tab5:
        st.subheader("File Integrity Hash Mismatch Demo")
        st.write("Demonstration of how changing a single byte invalidates SHA-256 file digests:")

        original_text = "Official Transfer Request: Send $1,000 to Account #123456"
        tampered_text = "Official Transfer Request: Send $1,000,000 to Account #999999"

        hash_orig = hashlib.sha256(original_text.encode()).hexdigest()
        hash_tamp = hashlib.sha256(tampered_text.encode()).hexdigest()

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("#### Original Content")
            st.code(original_text)
            st.markdown(f"**SHA-256 Digest:**\n`{hash_orig}`")

        with col2:
            st.markdown("#### Tampered Content")
            st.code(tampered_text)
            st.markdown(f"**SHA-256 Digest:**\n`{hash_tamp}`")

        st.error("❌ **Hash Verification MISMATCH**: The SHA-256 checksums are completely different due to the avalanche effect of cryptographic hashing.")

import streamlit as st
from utils import validation, vault
from utils.theme import page_header


def render():
    page_header(
        "Local Password Manager",
        "Store credentials in an encrypted local vault using a master password.",
        "🗄️",
    )

    vault.initialize()

    if "vault_unlocked" not in st.session_state:
        st.session_state.vault_unlocked = False
        st.session_state.vault_fernet = None

    if not vault.has_master_password():
        st.info("Create a master password to initialize the local encrypted vault.")
        master_password = st.text_input(
            "Master password",
            type="password",
            help="Choose a strong master password. It is never stored in plaintext.",
        )
        confirm_password = st.text_input(
            "Confirm master password",
            type="password",
        )
        if st.button("Create vault"):
            if not validation.is_valid_password(master_password):
                st.error("Master password must be at least 8 characters.")
            elif master_password != confirm_password:
                st.error("Master password and confirmation do not match.")
            else:
                try:
                    vault.set_master_password(master_password)
                    st.success("Master password created. Vault is ready.")
                except Exception as exc:
                    st.error("Unable to create vault: " + str(exc))
        return

    if not st.session_state.vault_unlocked:
        st.info("Unlock the vault with your master password.")
        unlock_password = st.text_input(
            "Master password",
            type="password",
            key="unlock_password",
        )
        if st.button("Unlock vault"):
            try:
                fernet = vault.unlock_vault(unlock_password)
                st.session_state.vault_unlocked = True
                st.session_state.vault_fernet = fernet
                st.success("Vault unlocked.")
            except Exception:
                st.error("Unlock failed. Check your master password.")
        return

    fernet = st.session_state.vault_fernet
    if not fernet:
        st.error("Vault state is invalid. Please reload the page and unlock again.")
        return

    st.success("Vault is unlocked.")
    if st.button("Lock vault"):
        st.session_state.vault_unlocked = False
        st.session_state.vault_fernet = None
        st.rerun()

    with st.expander("Add new credential", expanded=True):
        service = st.text_input("Service or website")
        username = st.text_input("Username or email")
        password = st.text_input("Password", type="password")
        notes = st.text_area("Notes (optional)")

        if st.button("Save credential"):
            if not validation.is_valid_service_name(service):
                st.error("Enter a valid service name.")
            elif not validation.is_valid_username(username):
                st.error("Enter a valid username.")
            elif not validation.is_valid_password(password):
                st.error("Password must be at least 8 characters.")
            else:
                try:
                    vault.add_entry(fernet, service, username, password, notes)
                    st.success("Credential saved securely.")
                except Exception as exc:
                    st.error("Unable to save credential: " + str(exc))

    search_query = st.text_input("Search credentials", help="Filter by service or username.")
    entries = vault.search_entries(fernet, search_query)

    if entries:
        st.write(f"Showing {len(entries)} credential(s).")
        for entry in entries:
            with st.expander(f"{entry['service']} — {entry['username']}"):
                st.write("**Service:**", entry["service"])
                st.write("**Username:**", entry["username"])
                st.write("**Password:**", entry["password"])
                st.write("**Notes:**", entry["notes"] or "(none)")
                st.write("**Created:**", entry["created_at"])
                st.write("**Updated:**", entry["updated_at"])
                if st.button("Delete entry", key=f"delete_{entry['id']}"):
                    try:
                        vault.delete_entry(entry["id"])
                        st.success("Entry deleted.")
                        st.rerun()
                    except Exception as exc:
                        st.error("Unable to delete entry: " + str(exc))
    else:
        st.info("No matching credentials found. Add a new credential above.")

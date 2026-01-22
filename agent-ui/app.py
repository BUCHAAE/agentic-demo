import json
import requests
import streamlit as st

st.set_page_config(page_title="Agent UI", layout="wide")

st.title("🧠 Agent UI (calls your FastAPI agent + tools)")

with st.sidebar:
    st.header("Settings")
    api_url = st.text_input("Agent API URL", value="http://localhost:8000/v1/chat/completions")
    timeout = st.number_input("HTTP timeout (seconds)", min_value=1, max_value=120, value=60)
    show_raw = st.checkbox("Show raw JSON response", value=True)

if "messages" not in st.session_state:
    st.session_state.messages = []  # chat history for the API


def call_agent(messages):
    payload = {"messages": messages}
    r = requests.post(api_url, json=payload, timeout=timeout)
    r.raise_for_status()
    return r.json()


def render_message(content: str):
    content = content or ""

    # 1) ASCII art → must be code
    looks_like_ascii = (
        ".----." in content
        and "COOL!" in content
        or "(______|______)" in content
    )
    if looks_like_ascii:
        st.code(content, language="text")
        return

    # 2) Markdown tables → keep markdown so tables render nicely
    looks_like_markdown_table = (
        "\n|" in content and "\n|---" in content  # classic markdown table pattern
    )
    if looks_like_markdown_table:
        st.markdown(content)
        return

    # 3) Otherwise: if multi-line, prefer markdown (keeps headings/bullets nice)
    if "\n" in content:
        st.markdown(content)
        return

    # 4) Single line: markdown is fine
    st.markdown(content)

# Render chat so far
for m in st.session_state.messages:
    role = m.get("role", "user")
    with st.chat_message(role):
        render_message(m.get("content", ""))

# Input box
user_text = st.chat_input("Type a prompt… (e.g. 'Use your tools to map API vs pages, then summarise for a manager')")

if user_text:
    # Add user message to history
    st.session_state.messages.append({"role": "user", "content": user_text})

    with st.chat_message("user"):
        render_message(user_text)

    # Call agent
    with st.chat_message("assistant"):
        with st.spinner("Calling agent API…"):
            try:
                resp = call_agent(st.session_state.messages)

                # OpenAI-style: choices[0].message.content
                content = ""
                try:
                    content = resp["choices"][0]["message"].get("content", "")
                except Exception:
                    content = "(Could not parse assistant content from response.)"

                render_message(content if content else "_(empty response)_")

                if show_raw:
                    with st.expander("Raw response JSON", expanded=False):
                        st.code(json.dumps(resp, indent=2), language="json")

                # Append assistant message to history (so conversation continues)
                st.session_state.messages.append({"role": "assistant", "content": content})

            except requests.HTTPError as e:
                st.error(f"HTTP error: {e}\n\nResponse body:\n{getattr(e.response, 'text', '')}")
            except requests.RequestException as e:
                st.error(f"Request failed: {e}")
            except Exception as e:
                st.error(f"Unexpected error: {e}")

# Convenience buttons
col1, col2, col3 = st.columns(3)
with col1:
    if st.button("Clear chat"):
        st.session_state.messages = []
        st.rerun()
with col2:
    st.caption("Tip: keep the raw JSON panel on while you’re debugging tool calls.")
with col3:
    st.caption("Default UI port: 8501")
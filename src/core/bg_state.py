import streamlit as st
import threading

@st.cache_resource
def _get_bg_store():
    return {
        "results": {},
        "running": set(),
        "progress": {},
        "lock": threading.Lock(),
        "summaries": {}
    }

_bg_store = _get_bg_store()
_bg_results = _bg_store["results"]
_bg_running = _bg_store["running"]
_bg_lock = _bg_store["lock"]

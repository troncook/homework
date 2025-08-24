# Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd mini-soar
   ```
2. **Configure API keys**
   ```bash
   mkdir -p .streamlit
   cat <<'TOML' > .streamlit/secrets.toml
OPENAI_API_KEY = "sk-..."
GEMINI_API_KEY = "AIza..."
GROK_API_KEY   = "gsk_..."
TOML
   ```
   Provide keys only for the services you intend to use.
3. **Build and run the containers**
   ```bash
   make up
   ```
   This trains the models (if missing) and launches the Streamlit UI on [http://localhost:8501](http://localhost:8501).
4. **Stop the application**
   ```bash
   make down
   ```
5. **Full cleanup**
   ```bash
   make clean
   ```

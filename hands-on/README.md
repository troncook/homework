# Cognitive SOAR – From Prediction to Attribution

This project extends the Mini‑SOAR example into a more intelligent system that not only predicts whether a URL is malicious but also attributes malicious links to a likely threat actor profile. Two models now power the workflow:

* **Phishing URL Detector** – a supervised classifier built with PyCaret.
* **Threat Actor Profiler** – an unsupervised clustering model that groups malicious URLs into three profiles (State‑Sponsored, Organized Cybercrime, Hacktivist).

When a URL is analysed, the classifier first determines if it is malicious. If so, the clustering model infers the probable actor category and the UI displays a short description of the actor’s typical motivation and tactics. Generative‑AI services are then used to propose a response plan.

## Features

* **Predictive Analytics** – URL classification using PyCaret.
* **Threat Attribution** – clustering‑based actor profiling (State‑Sponsored, Organized Cybercrime, Hacktivist).
* **Prescriptive Analytics** – integrates with Gemini, OpenAI and Grok for response plans.
* **Interactive UI** – Streamlit interface with dedicated “Threat Attribution” tab.
* **Containerised** – Docker & Docker Compose for reproducible deployment.
* **Simplified workflow** – `Makefile` targets for building and running the app.

## Prerequisites

Before you begin, ensure you have the following installed on your system:
-   [Docker](https://www.docker.com/get-started)
-   [Docker Compose](https://docs.docker.com/compose/install/) (often included with Docker Desktop)
-   [Make](https://www.gnu.org/software/make/) (pre-installed on most Linux/macOS systems; Windows users can use WSL or Chocolatey).
-   API keys for at least one Generative AI service (Gemini, OpenAI, or Grok).

## Setup & Installation

1.  **Clone the Repository**
    ```bash
    git clone <repository-url>
    cd mini-soar
    ```

2.  **Configure API Keys**
    This is the most important step. The application reads API keys from a `secrets.toml` file.

    -   Create the directory and file:
        ```bash
        mkdir -p .streamlit
        touch .streamlit/secrets.toml
        ```
    -   Open `.streamlit/secrets.toml` and add your API keys. Use the following template:
        ```toml
        # .streamlit/secrets.toml
        OPENAI_API_KEY = "sk-..."
        GEMINI_API_KEY = "AIza..."
        GROK_API_KEY = "gsk_..."
        ```
        *You only need to provide a key for the service(s) you intend to use.*

More detailed steps are available in [INSTALL.md](INSTALL.md).

## Running the Application

With the `Makefile`, running the application is simple.

-   **To build and start the application:**
    ```bash
    make up
    ```
    The first time you run this, it will download the necessary Docker images and build the application container. This may take a few minutes. Subsequent runs will be much faster.

-   Once it's running, open your web browser and go to:
    **[http://localhost:8501](http://localhost:8501)**

-   **To view the application logs:**
    ```bash
    make logs
    ```

-   **To stop the application:**
    ```bash
    make down
    ```

-   **To perform a full cleanup** (stops containers and removes generated model/data files):
    ```bash
    make clean
    ```

Manual test cases can be found in [TESTING.md](TESTING.md).

## Project Structure
```
mini-soar/
├── README.md
├── Makefile
├── app.py
├── train_model.py
├── genai_prescriptions.py
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── .streamlit/
    └── secrets.toml
```

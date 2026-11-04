```mermaid
flowchart TD
 A[User selects folder] --> B[Watchdog observer]
 B --> C[Filesystem handler]
 C --> D[Policy checks]
 C --> E[SHA-256 hashing]
 D --> F[SQLite]
 E --> F
 F --> G[Streamlit dashboard]
 F --> H[CSV JSON PDF reports]
```
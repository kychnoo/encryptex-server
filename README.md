# Encryptex Server 🔐
<p align="center">
    <a href="https://www.gnu.org/licenses/agpl-3.0.en.html"><img src="https://img.shields.io/badge/license-AGPL%20V3-blue.svg?longCache=true" alt="License"></a>
    <a href="https://github.com/kychnoo/encryptex-server"><img src="https://img.shields.io/github/actions/workflow/status/kychnoo/encryptex-server/CI.yml.svg" alt="Build"></a>
    <a href="https://rust-lang.org/"><img src="https://img.shields.io/badge/Rust-1.99%2B-orange.svg"></a>
</p>

A high-performance, asynchronous authentication & messaging backend written in Rust, built specifically for the **Encryptex** ecosystem.

Designed with strict cryptographic security, zero-trust state verification, and full protection against replay attacks via **Ed25519** nonce signatures.

---

## ✨ Features

* **Axum Core:** Type-safe, high-concurrency HTTP/WebSocket routing.
* **PostgreSQL & SQLx:** Compile-time verified SQL queries and clean migration tracking.

---

## 🛠️ Requirements

* **Rust** (1.99+ / Stable)
* **Docker** & **Docker Compose** (for local PostgreSQL instance)
* **sqlx-cli** (optional, for manual migration execution)

---

## 🚀 Quick Start
### 1. Clone the repository
```bash
git clone https://github.com/kychnoo/encryptex-server.git
cd encryptex-server
```

### 2. Configure Environment
Create a .env file in the root directory:
```env
DATABASE_URL=postgres://postgres:postgres@localhost:5432/encryptex_server
SERVER_PORT=8080
```
### 3. Spin up PostgreSQL
```bash
docker-compose up -d
```

### 4. Run Migrations & Start Server
```bash
sqlx migrate run
cargo run
```

## 🧪 Testing
Run all unit, integration, and state-validation tests:
```bash
cargo test
```

## 🚀 Starting
Run the application:
```bash
cargo run
```

---

## 📄 License
This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0).**

Under this license, if you modify or run a hosted version of this software as a network service, you must make your modified source code available to all users interacting with it. See the [LICENSE](LICENSE) file for complete details.
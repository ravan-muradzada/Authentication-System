
# 🔐 Authentication System – Node.js + Express + Prisma + Passport.js

This is a **production-ready authentication system** built with  **Node.js** ,  **Express** ,  **Prisma ORM** ,  **Redis** , and  **Passport.js** . It supports  **manual sign-up with OTP verification** ,  **Google OAuth sign-in** ,  **JWT-based access and refresh tokens** , and  **robust password reset flows** .

---

## 📁 Folder Structure

```
.
├── prisma/
│   └── schema.prisma             # Prisma schema
├── src/
│   ├── auth/                     # Business logic for authentication
│   ├── config/                   # Config files (e.g. Redis, DB, etc.)
│   ├── controllers/              # Route handlers (e.g. authController.js)
│   ├── generated/                # Auto-generated Prisma client
│   ├── middlewares/             # All middleware functions (e.g. JWT, validation)
│   ├── routers/                  # Express route definitions
│   ├── utils/                    # Helper functions
│   └── server.js                 # Entry point of the app
├── .env                          # Environment variables
├── .gitignore
├── docker-compose.yml           # Docker configuration for services like Redis
├── package.json
```

---

## 🚀 Features

* ✅ OTP-based sign-up and login
* 🔁 Access and refresh token system (JWT)
* 🚀 JWT checking using passport-jwt
* ✅ Password hashing
* 🔐 Google OAuth sign-up and login (using Passport.js)
* 🔒 Secure password reset mechanism
* 🛡️ Route protection via middleware
* 🧠 Token refreshing and session invalidation (with Redis)
* ❌ Limiting the number of request to per router.
* 🔒 Freezing an account after multiple unsuccessful login attempts
* **`🍪`** Using cookies for refresh tokens

---

## 🛠️ Technologies Used

* **Node.js** + **Express.js**
* **Prisma ORM** + **PostgreSQL**
* **Redis** for temporary storage (OTP, refresh token saving)
* **Passport.js** for Google OAuth and JWT validation
* **JWT** for stateless authentication
* **Docker** for PostgreSQL and redis (via `docker-compose.yml`)
* **SendGrid** for email sending
* **Express rate limit** to restrict requests from the one source

---

## 🧭 API Routes

### 🔐 Authentication

#### 📮 Manual Sign-Up & OTP Flow

* `POST /auth/sign-up`

  → Initiates OTP-based signup (expects email and password).
* `POST /auth/verify-otp`

  → Verifies OTP and completes registration.
* `POST /protected/add-other-credentials`

  → After OTP, user adds username (requires JWT).

#### 👤 Manual Login

* `POST /auth/login`

  → Initiates login (OTP sent to email or phone).
* `POST /auth/verify-login`

  → Verifies login OTP and issues tokens.

#### 🔄 Token Management

* `POST /protected/refresh`

  → Provides new access & refresh tokens (using refresh token). Frontend needs to handle it automatically.
* `POST /protected/logout`

  → Logs user out.

---

### 🔑 Google OAuth

* `GET /auth/google`

  → Redirects user to Google for authentication.
* `GET /auth/google/callback`

  → Handles OAuth callback and issues tokens.
* `GET /auth/login-failed`

  → Triggered if Google login fails.

---

### 🔧 Password Management

* `PATCH /auth/change-password`

  → Changes password (JWT-protected).
* `POST /auth/forget-password`

  → Sends reset token via email.
* `PATCH /auth/reset-password/:token`

  → Resets password using token.

---

### 🔐 Example Protected Route

* `GET /protected/protected-route-example`

  → Returns simple success message (JWT-protected).

---

## ⚙️ Environment Variables

You should define the following keys in your `.env` file:

```
DATABASE_URL=your_postgres_connection_url
SENDGRIDAPIKEY=your_sendgrid_api_key
EMAIL_FROM=email_used_for_sendgrid
ACCESS_TOKEN_SECRET=your_access_secret
REFRESH_TOKEN_SECRET=your_refresh_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

---

## ▶️ Getting Started

1. **Install dependencies:**
   ```bash
   npm install
   ```
2. **Run Prisma migrations:**
   ```bash
   npx prisma migrate dev
   ```
3. **Start Docker services (for Redis and PostgreSQL):**
   ```bash
   docker-compose up -d
   ```
4. **Start the server:**
   ```bash
   npm start
   ```

# 🔐 Secure Code Review – Food Delivery System

---

## 🎓 Coursework-Based Secure Code Review Project

As a part of my coursework, I conducted a **Secure Code Review** of the [Food Delivery System](https://github.com/enatega/food-delivery-multivendor), a full-fledged food ordering and logistics platform inspired by apps like UberEats and FoodPanda. This project includes:

- Customer App
- Rider App
- Restaurant App
- Web Dashboard for Admin
- API Backend (licensed)

---

## 🧾 Project Objective

> Choose a programming language and application.  
> Review the code for security vulnerabilities and provide recommendations for secure coding practices.  
> Use tools like **static code analyzers** or **manual code review**.

---

## 🛠️ Technologies Used

The Enatega system is built with:

- **Frontend**: React.js, React Native, Expo, React Navigation, React Router
- **Backend**: Node.js, Express.js, MongoDB (hosted), Firebase (for notifications/auth)
- **API & Auth**: GraphQL, Firebase Auth, JWT
- **Analytics/Monitoring**: Sentry, Amplitude
- **CI Tools**: EAS Build for mobile app builds

---

## 🔍 Secure Coding Analysis Tools Used

To perform static and manual code review, I explored the following **SAST tools**:

| Tool           | License      | Notes                                  |
|----------------|--------------|----------------------------------------|
| Bandit         | Open Source  | Python-oriented, some usage for scripts |
| HCL AppScan    | Free version | For Node.js & JavaScript vulnerabilities |
| Pyre           | Open Source  | Static analysis of JS & TypeScript      |
| Snyk           | Free Tier    | Known vulnerability scan in dependencies |
| ESLint + Plugins | Open Source | Catches risky JS/React patterns         |

---

## 📚 OWASP Alignment – Top 10 Vulnerabilities Reviewed

As part of the **Manual Code Review**, I evaluated the project against **OWASP Top 10** vulnerabilities. Below are key observations:

### ✅ 1. Broken Access Control
- **Issue Identified**: Routes lacked granular authorization middleware in some parts of the GraphQL schema.
- **Fix Applied**: Added **JWT token validation and role-based guards** on protected routes and resolvers.

### ✅ 2. Cryptographic Failures
- **Issue Identified**: Sensitive data like email/passwords stored using Firebase auth (secure) – no major issues.
- **Improvement**: Recommended enabling **email encryption** at DB level using AES.

### 🔧 3. Injection
- **Issue Identified**: Some dynamic MongoDB queries could be manipulated.
- **Fix Suggested**: Use **MongoDB parameterized queries** or Mongoose's safer API.

### 🔧 4. Insecure Design
- Suggest adding **Rate Limiting**, **Brute Force Protection**, and **2FA** for admin login.
  
### 🔧 5. Security Misconfiguration
- Found hardcoded secrets in sample files like:
  - `helpers/config.js`
  - `helpers/credentials.js`

  🔐 **Fix Applied**: Moved sensitive data to `.env` files and added `.env` to `.gitignore`

---

## 🔐 Additional Secure Coding Recommendations

- **Transport Layer Security**: Ensure all API endpoints are behind HTTPS only (especially mobile).
- **Session Management**: Expire JWTs after a set time; implement token refresh logic.
- **Firebase Rules**: Enforce **Firestore security rules** to avoid privilege escalation from client apps.
- **Dependency Audit**: Use `npm audit fix` and tools like `Snyk` to regularly scan for outdated/vulnerable packages.

---

## 🧪 Example Fixes from My Manual Code Review

| Issue | File | Fix |
|-------|------|-----|
| Hardcoded API Key | `config.js` | Moved to `.env` |
| Unvalidated input | `user.resolver.js` | Added input sanitization via `validator` package |
| Missing auth on resolver | `restaurant.resolver.js` | Wrapped in `isAuthenticated` middleware |
| Insecure CORS policy | `server.js` | Restricted origins to whitelisted domains |

---

## 🚀 Project Modules Reviewed

I cloned and set up the following modules for testing:

1. **Admin Dashboard (Next.js)** – `npm run dev`
2. **Customer Web (React.js)** – `npm start`
3. **Mobile Apps (Expo)** – Tested using `Expo Go` on Android
4. **Rider App & Restaurant App** – Reviewed for permissions and data flow
5. **API Code (Limited)** – Reviewed config files and setup scripts (backend is licensed)

---

## 🧠 Learning Outcome

This project provided me with hands-on experience in:

- Applying **OWASP Top 10** in real-world apps
- Using **SAST tools** to uncover potential flaws
- Fixing broken access controls and insecure API exposures
- Understanding the secure handling of credentials and secrets
- Evaluating authentication and authorization schemes

---

## 📌 Conclusion

> _Securing an application is just as important as building it._

Performing a Secure Code Review on a **real-world, production-grade application** gave me deeper insight into:

- Best practices for web/mobile API security
- How to structure secure full-stack apps
- Real-world DevSecOps workflows and tooling

This experience has significantly improved my awareness of **security flaws**, and I will continue practicing secure development beyond this coursework.

---

## 🔗 Project Link

- GitHub Repository: [Food Delivery System](https://github.com/enatega/food-delivery-multivendor)


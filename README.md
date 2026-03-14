# MODULE 1 — Authentication & Institution Setup

## Purpose
Handles everything related to user identity, access control, and institution onboarding.
This module is the security foundation — every other module depends on it.

## Files Included

### Backend
| File | Responsibility |
|------|---------------|
| `backend/db.js` | PostgreSQL connection pool — shared by all modules |
| `backend/server.js` | Express app entry point — registers all routes |
| `backend/package.json` | All npm dependencies |
| `backend/.env.example` | Environment variable template |
| `backend/middleware/auth.js` | JWT verify middleware — protects all routes |
| `backend/controllers/authController.js` | Register, Login, Activate, Add Counsellor |
| `backend/routes/auth.js` | `/api/auth/*` route definitions |
| `backend/services/emailService.js` | Nodemailer — sends follow-up emails |

### Database
| File | Responsibility |
|------|---------------|
| `database/schema_postgres.sql` | Full PostgreSQL schema — run this first in pgAdmin |

### Frontend
| File | Responsibility |
|------|---------------|
| `frontend/src/pages/Landing.jsx` | Public landing page |
| `frontend/src/pages/Login.jsx` | Login form — Admin & Counsellor |
| `frontend/src/pages/Register.jsx` | Admin self-registration |
| `frontend/src/pages/ActivateAccount.jsx` | Counsellor account activation |
| `frontend/src/services/api.js` | Axios instance — baseURL + auth header |

## API Endpoints
```
POST /api/auth/register      Admin self-registration
POST /api/auth/login         Login → returns JWT token
POST /api/auth/activate      Counsellor sets their password
POST /api/auth/counsellors   Admin adds a counsellor (protected)
GET  /api/auth/counsellors   List all counsellors (protected)
GET  /api/auth/branches      Get all branch options
```

## Key Logic
- Passwords hashed with bcrypt (10 rounds)
- JWT signed with JWT_SECRET, expires in 10 hours
- Counsellors start with password = NULL and is_active = FALSE
- Counsellors self-activate using their email — no admin password sharing
- Every protected route goes through `middleware/auth.js` JWT verification

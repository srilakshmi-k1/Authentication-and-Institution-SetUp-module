# MODULE 3 — Prediction & Risk Engine

## Purpose
The intelligence core of EduSafeGuard.
Classifies students into risk tiers, generates AI-style suggestions,
and manages the full counsellor follow-up workflow including email alerts.

## Files Included

### Backend
| File | Responsibility |
|------|---------------|
| `backend/services/riskService.js` | Risk classification + AI suggestion generation |
| `backend/controllers/studentController.js` | getStudent, getAISuggestion (uses riskService) |
| `backend/controllers/followupController.js` | Add note, send email, list follow-ups |
| `backend/services/emailService.js` | Nodemailer HTML email sender |
| `backend/routes/students.js` | `/api/students/:id/ai-suggestion` |
| `backend/routes/followups.js` | `/api/followups/*` route definitions |

### Frontend
| File | Responsibility |
|------|---------------|
| `frontend/src/pages/StudentDetails.jsx` | Full student profile + AI suggestions + follow-up history |
| `frontend/src/components/RiskBadge.jsx` | Coloured risk badge component (High/Moderate/Safe) |
| `frontend/src/components/FollowupForm.jsx` | Note form with date picker + Save / Save & Email buttons |
| `frontend/src/services/api.js` | Axios instance (shared) |

## API Endpoints
```
GET  /api/students/:id               Student full detail with risk level
GET  /api/students/:id/ai-suggestion Generate AI suggestions + log to DB
POST /api/followups                  Save note, schedule follow-up, optionally send email
GET  /api/followups/student/:id      All follow-ups for a specific student
GET  /api/followups/mine             Counsellor's own follow-up history
```

## Risk Classification Rules (riskService.js)
```
CGPA < 5.0  AND Attendance < 60%  →  High Risk     (risk_level_id = 1)
CGPA 5–7    OR  Attendance 60–75% →  Moderate Risk  (risk_level_id = 2)
CGPA > 7.0  AND Attendance > 75%  →  Safe           (risk_level_id = 3)
All other combinations            →  Moderate Risk  (default)
```

## AI Suggestion Logic (riskService.js)
Rule-based suggestions — no external API required:
- CGPA < 5 → peer tutoring, study plan, past papers
- CGPA 5–7 → group study, bi-weekly check-ins
- CGPA > 7 → research/internship recommendations
- Attendance < 60 → family meeting, barrier identification
- Attendance 60–75 → attendance tracking, reminders
- High Risk overall → immediate counselling, improvement plan

Each suggestion is stored in `ai_guidance_logs` table.

## Email Service (emailService.js)
Triggered when counsellor checks "Send Email" on FollowupForm.
- Transport: Gmail via Nodemailer
- Requires: EMAIL_USER and EMAIL_PASS (Gmail App Password) in .env
- Sends: Styled HTML email with note, date, counsellor name
- Returns: { success: true } or { success: false, error: string }

# MODULE 4 — Dashboards & UI

## Purpose
All visual interfaces — admin overview, counsellor workspace, shared layout components,
routing, and global styling. This module is what the end user sees and interacts with.

## Files Included

### Backend
| File | Responsibility |
|------|---------------|
| `backend/controllers/dashboardController.js` | Admin stats + counsellor stats queries |
| `backend/routes/dashboard.js` | `/api/dashboard/*` route definitions |

### Frontend
| File | Responsibility |
|------|---------------|
| `frontend/src/App.js` | React Router — all route definitions |
| `frontend/src/index.js` | React entry point |
| `frontend/src/index.css` | Global CSS styles |
| `frontend/src/pages/AdminDashboard.jsx` | Admin home — stats cards, branch breakdown, recent students |
| `frontend/src/pages/CounsellorDashboard.jsx` | Counsellor home — assigned students, risk summary |
| `frontend/src/components/Sidebar.jsx` | Navigation sidebar — role-aware links |
| `frontend/src/components/StudentTable.jsx` | Reusable sortable student list table |
| `frontend/src/components/RiskBadge.jsx` | Coloured pill badge: High / Moderate / Safe |
| `frontend/src/services/api.js` | Axios instance — baseURL + auto auth header |

## API Endpoints
```
GET /api/dashboard/admin       Full admin stats: totals, risk counts, branch breakdown,
                               recent students, counsellor load
GET /api/dashboard/counsellor  Counsellor stats: assigned count by risk tier, follow-up count
```

## Admin Dashboard Data
```json
{
  "stats": {
    "total": 150,
    "high_risk": 23,
    "moderate_risk": 67,
    "safe": 60,
    "assigned": 110,
    "unassigned": 40,
    "counsellors": 8
  },
  "branchData": [...],
  "recentStudents": [...],
  "counsellorLoad": [...]
}
```

## Routing Structure (App.js)
```
/                   → Landing page (public)
/login              → Login
/register           → Admin register
/activate           → Counsellor activate
/admin/dashboard    → AdminDashboard    [admin only]
/admin/upload       → UploadStudents    [admin only]
/admin/assign       → AssignStudents    [admin only]
/admin/counsellors  → ManageCounsellors [admin only]
/counsellor/dashboard → CounsellorDashboard [counsellor only]
/student/:id        → StudentDetails   [both roles]
```

## Shared Components
- **Sidebar** — reads role from localStorage JWT and shows correct nav links
- **StudentTable** — accepts `students` prop, renders sortable rows with RiskBadge
- **RiskBadge** — colour-coded: red = High Risk, amber = Moderate, green = Safe
- **api.js** — all API calls go through this; automatically attaches Bearer token

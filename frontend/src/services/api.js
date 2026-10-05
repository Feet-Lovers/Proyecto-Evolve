const USE_MOCKS = false
const API_BASE = import.meta.env.VITE_API_URL || ''  // '' = mismo origen (via Nginx: /api, /ws)
export const config = { USE_MOCKS, API_BASE }

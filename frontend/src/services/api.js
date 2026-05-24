const USE_MOCKS = false
const API_BASE = import.meta.env.VITE_API_URL || `http://${window.location.hostname}:8000`
export const config = { USE_MOCKS, API_BASE }

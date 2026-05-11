const USE_MOCKS = false // Cambiar a false cuando el backend esté listo

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export const config = { USE_MOCKS, API_BASE }
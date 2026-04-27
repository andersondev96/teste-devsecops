/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'academico-bg': '#f8fafc',
        'academico-primary': '#1e293b',
        'severidade-alta': '#ef4444',
        'severidade-media': '#f59e0b',
        'severidade-baixa': '#10b981',
      }
    },
  },
  plugins: [],
}
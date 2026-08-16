import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      // The API app (T-6.x) runs on 8000 in dev; proxy so the browser
      // only ever talks to one origin and cookies/headers stay simple.
      '/api': 'http://127.0.0.1:8000',
      '/kb': 'http://127.0.0.1:8000',
      '/model-versions': 'http://127.0.0.1:8000',
      '/threat-model-projects': 'http://127.0.0.1:8000',
      '/deep-analysis-results': 'http://127.0.0.1:8000',
      '/login_check': 'http://127.0.0.1:8000',
      '/api-tokens': 'http://127.0.0.1:8000',
    },
  },
})

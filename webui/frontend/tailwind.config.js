/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        slateBg: '#f4f6fa',
        ink: '#10203a'
      },
      boxShadow: {
        soft: '0 10px 24px rgba(16, 27, 48, 0.08)'
      }
    }
  },
  plugins: []
}

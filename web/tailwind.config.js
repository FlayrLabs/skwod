/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        display: ['"Bricolage Grotesque"', 'sans-serif'],
        heading: ['Orbitron', 'sans-serif'],
        body: ['"Hanken Grotesk"', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      colors: {
        ink: '#07070c',
        squid: { DEFAULT: '#3ad7ff', deep: '#3a6bff', indigo: '#7a5cff' },
      },
    },
  },
  plugins: [],
}

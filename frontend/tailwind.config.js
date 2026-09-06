/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        emit: {
          bg: '#000000',
          'bg-secondary': '#101010',
          surface: '#101010',
          'surface-elevated': '#181818',
          border: '#222222',
          'border-highlight': '#333333',
          green: '#00FF00',
          'green-dim': '#00AA00',
          orange: '#FF8800',
          'orange-dim': '#CC6600',
          purple: '#BB88FF',
          'purple-dim': '#8855CC',
          red: '#FF3333',
          'red-dim': '#CC0000',
          violet: '#BB88FF',
          'violet-light': '#D4AAFF',
          teal: '#00FF00',
          amber: '#FF8800',
          blue: '#38BDF8',
          muted: '#666666',
          text: '#FFFFFF',
          'text-dim': '#AAAAAA',
          'text-muted': '#666666',
        },
      },
      fontFamily: {
        sans: ['JetBrains Mono', 'Roboto Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
        mono: ['JetBrains Mono', 'Roboto Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      boxShadow: {
        'forensic-glow-green': '0 0 15px rgba(0, 255, 0, 0.35)',
        'forensic-glow-orange': '0 0 15px rgba(255, 136, 0, 0.35)',
        'forensic-glow-purple': '0 0 15px rgba(187, 136, 255, 0.35)',
        'forensic-card': '0 4px 20px -2px rgba(0, 0, 0, 0.8)',
      },
    },
  },
  plugins: [],
}

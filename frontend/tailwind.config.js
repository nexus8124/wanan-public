/** @type {import('tailwindcss').Config} */
// 配色对齐 方案展示.html 的暗色科技风
export default {
  content: ['./index.html', './src/**/*.{vue,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // 深色底（与方案 HTML 一致）
        bg: '#070b16',
        'bg-2': '#0d1322',
        card: '#131a2c',
        'card-hover': '#1a2238',
        border: '#1f2a44',
        'border-light': '#2a3754',
        text: '#e8ecf5',
        'text-dim': '#8a96b4',
        'text-mute': '#5a6685',
        // 强调色
        cyan: '#00d9ff',
        purple: '#a78bfa',
        pink: '#f472b6',
        green: '#34d399',
        yellow: '#fbbf24',
        orange: '#fb923c',
        red: '#f87171',
      },
      fontFamily: {
        sans: ['Inter', 'Noto Sans SC', 'sans-serif'],
        mono: ['JetBrains Mono', 'Consolas', 'monospace'],
      },
      animation: {
        'pulse-dot': 'pulse-dot 2s ease-in-out infinite',
        'slide-up': 'slide-up 0.4s ease-out',
        'fade-in': 'fade-in 0.5s ease-out',
      },
      keyframes: {
        'pulse-dot': {
          '0%, 100%': { opacity: '1', transform: 'scale(1)' },
          '50%': { opacity: '0.5', transform: 'scale(1.3)' },
        },
        'slide-up': {
          '0%': { opacity: '0', transform: 'translateY(20px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'fade-in': {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
      },
    },
  },
  plugins: [],
}

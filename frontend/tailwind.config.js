/** @type {import('tailwindcss').Config} */
// 双主题 SOC 控制台:亮=冷纸白编辑风,暗=深空蓝黑作战室。
// 色值统一由 style.css 的 CSS 变量提供(唯一色源),此处仅做映射,
// class 名沿用既有约定(bg/card/cyan/...),透明度修饰符(bg-cyan/10)继续可用。
// 形状系统:全站直角(rounded-none)为签名,保持一致,不混用圆角。
export default {
  content: ['./index.html', './src/**/*.{vue,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: 'rgb(var(--bg) / <alpha-value>)',
        'bg-2': 'rgb(var(--bg-2) / <alpha-value>)',
        card: 'rgb(var(--card) / <alpha-value>)',
        'card-hover': 'rgb(var(--card-hover) / <alpha-value>)',
        border: 'rgb(var(--border) / <alpha-value>)',
        'border-light': 'rgb(var(--border-light) / <alpha-value>)',
        text: 'rgb(var(--text) / <alpha-value>)',
        'text-dim': 'rgb(var(--text-dim) / <alpha-value>)',
        'text-mute': 'rgb(var(--text-mute) / <alpha-value>)',
        // 强调蓝底上的文字色,取代散落各处的硬编码
        'on-accent': 'rgb(var(--on-accent) / <alpha-value>)',
        // cyan 槽位 = 主强调(电光蓝),沿用既有 class
        cyan: 'rgb(var(--cyan) / <alpha-value>)',
        purple: 'rgb(var(--purple) / <alpha-value>)',
        pink: 'rgb(var(--pink) / <alpha-value>)',
        green: 'rgb(var(--green) / <alpha-value>)',
        yellow: 'rgb(var(--yellow) / <alpha-value>)',
        red: 'rgb(var(--red) / <alpha-value>)',
      },
      fontFamily: {
        // Space Grotesk 仅覆盖拉丁字形,CJK 自动回落 Noto Sans SC
        sans: ['Space Grotesk', 'Noto Sans SC', 'sans-serif'],
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

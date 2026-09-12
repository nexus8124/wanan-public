// 三态主题管理:system(跟随系统)/light/dark
// 持久化到 localStorage,通过 <html data-theme> 锁定,未锁定时由
// style.css 的 prefers-color-scheme 媒体查询自动切换。
export type ThemeMode = 'system' | 'light' | 'dark'

const STORAGE_KEY = 'security-alert-theme'
const VALID_MODES: ThemeMode[] = ['system', 'light', 'dark']

export function loadThemeMode(): ThemeMode {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored && (VALID_MODES as string[]).includes(stored)) return stored as ThemeMode
  } catch {
    /* localStorage 不可用时回退 system */
  }
  return 'system'
}

export function applyThemeMode(mode: ThemeMode): void {
  const root = document.documentElement
  if (mode === 'system') {
    root.removeAttribute('data-theme')
  } else {
    root.setAttribute('data-theme', mode)
  }
}

export function persistThemeMode(mode: ThemeMode): void {
  try {
    if (mode === 'system') localStorage.removeItem(STORAGE_KEY)
    else localStorage.setItem(STORAGE_KEY, mode)
  } catch {
    /* 忽略持久化失败 */
  }
}

// 初始化:应用已存偏好,并跟随系统变化(仅在 system 态需要重算派生样式时触发重绘钩子)
export function initTheme(): void {
  applyThemeMode(loadThemeMode())
  const media = window.matchMedia('(prefers-color-scheme: dark)')
  media.addEventListener('change', () => {
    // data-theme 缺省时 CSS 媒体查询已自动换肤;此监听留给未来需要 JS 感知主题的场景
    document.documentElement.dispatchEvent(new CustomEvent('themechange', { detail: media.matches }))
  })
}

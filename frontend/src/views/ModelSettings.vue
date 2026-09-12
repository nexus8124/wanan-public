<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import {
  PhArrowCounterClockwise,
  PhCheck,
  PhFloppyDisk,
  PhGear,
  PhKey,
  PhPlug,
  PhPlus,
  PhTrash,
  PhWarning,
  PhX,
} from '@phosphor-icons/vue'
import {
  getModelConfig,
  resetModelConfig,
  saveModelConfig,
  testModelProvider,
  type ModelConfig,
} from '../api/client'
import { reloadModelSelection } from '../modelSelection'
import ConfirmDialog from '../components/ConfirmDialog.vue'

// ---------- 表单状态 ----------

interface EditableModel {
  id: string
  label: string
}

interface EditableProvider {
  id: string
  display_name: string
  base_url: string
  enabled: boolean
  builtin: boolean
  saved: boolean // 已存在于服务端 → id 锁定
  api_key_set: boolean
  api_key_preview: string
  api_key_source: string
  keyInput: string // 新输入的 key；空 = 未修改
  clearKey: boolean // 清除文件里已保存的 key
  models: EditableModel[]
}

interface TestState {
  running: boolean
  ok: boolean
  message: string
}

const loading = ref(false)
const saving = ref(false)
const errorMsg = ref('')
const noticeMsg = ref('')
const configFile = ref('')
const configFromFile = ref(false)
const providers = ref<EditableProvider[]>([])
const defaultProvider = ref('')
const defaultModel = ref('')
const temperature = ref(0.1)
const testStates = ref<Record<string, TestState>>({})

let loadedSnapshot = ''

interface ConfirmRequest {
  title: string
  body: string
  confirmLabel: string
  tone: 'accent' | 'danger'
  action: () => void
}
const confirmRequest = ref<ConfirmRequest | null>(null)

// ---------- 初始化 ----------

function toEditable(raw: ModelConfig['providers'][number]): EditableProvider {
  return {
    id: raw.id,
    display_name: raw.display_name,
    base_url: raw.base_url,
    enabled: raw.enabled,
    builtin: raw.builtin,
    saved: true,
    api_key_set: Boolean(raw.api_key_set),
    api_key_preview: raw.api_key_preview || '',
    api_key_source: raw.api_key_source || 'none',
    keyInput: '',
    clearKey: false,
    models: raw.models.map((m) => ({ id: m.id, label: m.label })),
  }
}

function initForm(config: ModelConfig) {
  configFile.value = config.config_file
  configFromFile.value = config.from_file
  providers.value = config.providers.map(toEditable)
  defaultProvider.value = config.defaults.provider
  defaultModel.value = config.defaults.model
  temperature.value = config.defaults.temperature
  testStates.value = {}
  loadedSnapshot = serializeForm()
}

function serializeForm(): string {
  return JSON.stringify({
    default_provider: defaultProvider.value,
    default_model: defaultModel.value,
    temperature: temperature.value,
    providers: providers.value.map((p) => ({
      id: p.id.trim(),
      display_name: p.display_name.trim(),
      base_url: p.base_url.trim(),
      enabled: p.enabled,
      models: p.models.map((m) => ({ id: m.id.trim(), label: (m.label.trim() || m.id.trim()) })),
      key: p.clearKey ? '__clear__' : (p.keyInput.trim() || null),
    })),
  })
}

const isDirty = computed(() => serializeForm() !== loadedSnapshot)

async function load() {
  loading.value = true
  errorMsg.value = ''
  try {
    initForm(await getModelConfig())
  } catch (e: any) {
    errorMsg.value = e.message
  } finally {
    loading.value = false
  }
}

onMounted(load)

// ---------- 默认厂商 / 模型联动 ----------

const defaultProviderEntry = computed(() =>
  providers.value.find((p) => p.id === defaultProvider.value) || null,
)

function changeDefaultProvider(event: Event) {
  const id = (event.target as HTMLSelectElement).value
  defaultProvider.value = id
  const entry = providers.value.find((p) => p.id === id)
  defaultModel.value = entry?.models[0]?.id || ''
}

function changeDefaultModel(event: Event) {
  defaultModel.value = (event.target as HTMLSelectElement).value
}

// ---------- 厂商增删 ----------

function addProvider() {
  providers.value.push({
    id: '',
    display_name: '',
    base_url: '',
    enabled: true,
    builtin: false,
    saved: false,
    api_key_set: false,
    api_key_preview: '',
    api_key_source: 'none',
    keyInput: '',
    clearKey: false,
    models: [{ id: '', label: '' }],
  })
}

function requestRemoveProvider(provider: EditableProvider) {
  const name = provider.display_name || provider.id || '未命名厂商'
  confirmRequest.value = {
    title: '删除模型厂商',
    body: `将删除厂商「${name}」及其全部模型条目。${
      provider.builtin ? '内置厂商删除后可通过「恢复默认」找回。' : ''
    }`,
    confirmLabel: '删除厂商',
    tone: 'danger',
    action: () => {
      providers.value = providers.value.filter((p) => p !== provider)
      if (defaultProvider.value === provider.id) {
        const fallback = providers.value[0]
        defaultProvider.value = fallback?.id || ''
        defaultModel.value = fallback?.models[0]?.id || ''
      }
    },
  }
}

// ---------- 模型行 ----------

function addModel(provider: EditableProvider) {
  provider.models.push({ id: '', label: '' })
}

function removeModel(provider: EditableProvider, index: number) {
  provider.models.splice(index, 1)
  if (defaultProvider.value === provider.id && defaultModel.value) {
    const stillThere = provider.models.some((m) => m.id.trim() === defaultModel.value)
    if (!stillThere) defaultModel.value = provider.models[0]?.id.trim() || ''
  }
}

// ---------- API Key ----------

const PROVIDER_ID_RE = /^[a-z][a-z0-9_-]*$/

function keyPlaceholder(p: EditableProvider): string {
  if (p.clearKey) return '已清除（.env 中的 key 仍会生效）'
  if (p.api_key_source === 'file' && p.api_key_preview) return `已保存 ${p.api_key_preview}，留空保持不变`
  if (p.api_key_source === 'env' && p.api_key_set) return `来自 .env ${p.api_key_preview}，输入可覆盖`
  return '输入 API Key'
}

function clearFileKey(p: EditableProvider) {
  p.clearKey = !p.clearKey
  if (p.clearKey) p.keyInput = ''
}

// ---------- 保存 ----------

function validate(): string | null {
  const ids = new Set<string>()
  for (const p of providers.value) {
    const pid = p.id.trim()
    if (!PROVIDER_ID_RE.test(pid)) {
      return `厂商标识「${pid || '（空）'}」不合法：需以小写字母开头，仅含小写字母/数字/下划线/连字符`
    }
    if (ids.has(pid)) return `厂商标识重复：${pid}`
    ids.add(pid)
    const modelIds = p.models.map((m) => m.id.trim()).filter(Boolean)
    if (!modelIds.length) return `厂商「${pid}」至少需要一个模型`
    if (new Set(modelIds).size !== modelIds.length) {
      return `厂商「${pid}」的模型名重复`
    }
    if (p.enabled && p.base_url.trim() && !/^https?:\/\//i.test(p.base_url.trim())) {
      return `厂商「${pid}」的 Base URL 必须以 http(s):// 开头`
    }
  }
  if (!providers.value.length) return '至少需要一个模型厂商'
  if (!ids.has(defaultProvider.value)) return '默认厂商不存在，请重新选择'
  const entry = providers.value.find((p) => p.id === defaultProvider.value)
  if (entry && defaultModel.value && !entry.models.some((m) => m.id.trim() === defaultModel.value)) {
    return '默认模型不属于当前默认厂商，请重新选择'
  }
  const temp = Number(temperature.value)
  if (!Number.isFinite(temp) || temp < 0 || temp > 2) return '温度需在 0 到 2 之间'
  return null
}

async function save() {
  const invalid = validate()
  if (invalid) {
    errorMsg.value = invalid
    return
  }
  saving.value = true
  errorMsg.value = ''
  noticeMsg.value = ''
  try {
    const config = await saveModelConfig({
      default_provider: defaultProvider.value,
      default_model: defaultModel.value,
      temperature: Number(temperature.value),
      providers: providers.value.map((p) => ({
        id: p.id.trim(),
        display_name: p.display_name.trim() || p.id.trim(),
        base_url: p.base_url.trim(),
        enabled: p.enabled,
        api_key: p.clearKey ? '' : (p.keyInput.trim() || null),
        models: p.models
          .filter((m) => m.id.trim())
          .map((m) => ({ id: m.id.trim(), label: m.label.trim() || m.id.trim() })),
      })),
    })
    initForm(config)
    await reloadModelSelection()
    noticeMsg.value = '模型配置已保存并立即生效，顶栏模型目录已同步更新'
  } catch (e: any) {
    errorMsg.value = e.message
  } finally {
    saving.value = false
  }
}

function requestReset() {
  confirmRequest.value = {
    title: '恢复默认配置',
    body: '将删除本机的模型配置文件，回到内置厂商目录 + .env 配置。自定义厂商与页面保存的 API Key 会丢失。',
    confirmLabel: '恢复默认',
    tone: 'danger',
    action: async () => {
      errorMsg.value = ''
      noticeMsg.value = ''
      try {
        initForm(await resetModelConfig())
        await reloadModelSelection()
        noticeMsg.value = '已恢复默认配置（内置厂商 + .env）'
      } catch (e: any) {
        errorMsg.value = e.message
      }
    },
  }
}

// ---------- 连接测试 ----------

async function runTest(p: EditableProvider) {
  const pid = p.id.trim()
  if (!pid || !p.base_url.trim()) {
    testStates.value[pid] = { running: false, ok: false, message: '请先填写厂商标识与 Base URL' }
    return
  }
  testStates.value = { ...testStates.value, [pid]: { running: true, ok: false, message: '测试中…' } }
  try {
    const result = await testModelProvider({
      provider: pid,
      base_url: p.base_url.trim(),
      api_key: p.keyInput.trim() || undefined,
    })
    testStates.value = {
      ...testStates.value,
      [pid]: { running: false, ok: result.ok, message: result.message },
    }
  } catch (e: any) {
    testStates.value = {
      ...testStates.value,
      [pid]: { running: false, ok: false, message: e.message },
    }
  }
}

function keyStateText(p: EditableProvider): string {
  if (p.keyInput.trim()) return 'KEY 待保存（覆盖）'
  if (p.clearKey) return 'KEY 待清除'
  if (p.api_key_source === 'file') return 'KEY 已保存'
  if (p.api_key_set) return 'KEY 来自 .env'
  return 'KEY 未配置'
}

const inputClass = 'w-full min-w-0 max-w-full bg-bg border border-border rounded-none px-3 py-2.5 text-[13px] text-text focus:border-text outline-none disabled:opacity-50'
const labelClass = 'block text-[11px] uppercase tracking-wider text-text-mute mb-2'
</script>

<template>
  <div class="page-enter model-settings max-w-5xl mx-auto">
    <!-- 页头 -->
    <header class="flex flex-wrap items-end justify-between gap-4 mb-5">
      <div class="min-w-0">
        <p class="section-title mb-2">MODEL CONFIGURATION</p>
        <h1 class="text-2xl font-extrabold tracking-tight flex items-center gap-2.5">
          <PhGear :size="24" weight="bold" class="text-cyan" aria-hidden="true" /> 模型配置
        </h1>
        <p class="mt-2 text-sm text-text-dim leading-relaxed max-w-2xl">
          厂商、模型与 API Key 在此集中管理，保存后立即生效，无需重启服务。
          配置写入本机 <code class="font-mono text-[12px] text-cyan">{{ configFile || 'data/model_config.json' }}</code>（不入库）；
          未在页面保存的 API Key 自动回落 <code class="font-mono text-[12px] text-cyan">.env</code>。
        </p>
      </div>
      <div class="flex items-center gap-2">
        <button
          type="button"
          :disabled="loading || saving || !configFromFile"
          :title="configFromFile ? '删除配置文件，回到内置目录 + .env' : '当前已是默认配置'"
          class="px-4 py-2 rounded-none text-sm font-bold border border-red/40 bg-red/10 text-red hover:bg-red/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed inline-flex items-center gap-1.5"
          @click="requestReset"
        >
          <PhArrowCounterClockwise :size="14" weight="bold" aria-hidden="true" /> 恢复默认
        </button>
        <button
          type="button"
          :disabled="loading || saving || !isDirty"
          :title="isDirty ? '保存到配置文件并立即生效' : '没有待保存的修改'"
          class="px-4 py-2 rounded-none text-sm font-bold border transition-all disabled:opacity-40 disabled:cursor-not-allowed inline-flex items-center gap-1.5"
          :class="saving
            ? 'bg-bg-2 text-text-mute border-border'
            : 'bg-cyan text-on-accent border-cyan hover:bg-text hover:text-bg hover:border-text'"
          @click="save"
        >
          <PhFloppyDisk :size="14" weight="fill" aria-hidden="true" />
          {{ saving ? '保存中…' : '保存配置' }}
        </button>
      </div>
    </header>

    <!-- 提示条 -->
    <div
      v-if="errorMsg"
      class="mb-4 px-4 py-3 border border-red/40 bg-red/10 text-red text-[13px] flex items-start gap-2"
      role="alert"
    >
      <PhWarning :size="16" weight="bold" class="flex-none mt-0.5" aria-hidden="true" />
      <span class="min-w-0 break-all">{{ errorMsg }}</span>
      <button type="button" class="ml-auto flex-none hover:text-text" aria-label="关闭错误提示" @click="errorMsg = ''">
        <PhX :size="14" weight="bold" aria-hidden="true" />
      </button>
    </div>
    <div
      v-if="noticeMsg"
      class="mb-4 px-4 py-3 border border-green/40 bg-green/10 text-green text-[13px] flex items-start gap-2"
      role="status"
    >
      <PhCheck :size="16" weight="bold" class="flex-none mt-0.5" aria-hidden="true" />
      <span class="min-w-0">{{ noticeMsg }}</span>
      <button type="button" class="ml-auto flex-none hover:text-text" aria-label="关闭提示" @click="noticeMsg = ''">
        <PhX :size="14" weight="bold" aria-hidden="true" />
      </button>
    </div>

    <!-- 全局默认 -->
    <section class="card p-4 sm:p-5 mb-5">
      <h2 class="font-bold text-base flex items-center gap-2 mb-4">
        <PhGear :size="17" weight="bold" class="text-cyan" aria-hidden="true" /> 全局默认
        <span class="ml-auto text-[11px] font-normal text-text-mute">研判与评测未显式指定模型时使用</span>
      </h2>
      <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-[minmax(220px,1fr)_minmax(220px,1fr)_160px]">
        <label class="min-w-0">
          <span :class="labelClass">默认厂商</span>
          <select :value="defaultProvider" :class="inputClass" @change="changeDefaultProvider">
            <option v-for="p in providers" :key="p.id" :value="p.id">
              {{ p.display_name || p.id || '（未命名）' }}
            </option>
          </select>
        </label>
        <label class="min-w-0">
          <span :class="labelClass">默认模型</span>
          <select :value="defaultModel" :class="inputClass" @change="changeDefaultModel">
            <option v-for="m in defaultProviderEntry?.models || []" :key="m.id" :value="m.id">
              {{ m.label || m.id }}
            </option>
          </select>
        </label>
        <label class="min-w-0">
          <span :class="labelClass">温度</span>
          <input
            v-model.number="temperature"
            type="number"
            min="0"
            max="2"
            step="0.1"
            :class="inputClass"
          />
        </label>
      </div>
    </section>

    <!-- 厂商列表 -->
    <section class="mb-2 flex items-center justify-between gap-3">
      <h2 class="font-bold text-base flex items-center gap-2">
        厂商与模型
        <span class="text-[11px] font-normal text-text-mute">共 {{ providers.length }} 个</span>
      </h2>
      <button
        type="button"
        class="px-3 py-2 rounded-none text-[13px] font-bold border border-cyan/50 text-cyan hover:bg-cyan/10 transition-all inline-flex items-center gap-1.5"
        @click="addProvider"
      >
        <PhPlus :size="14" weight="bold" aria-hidden="true" /> 添加自定义厂商
      </button>
    </section>

    <div v-if="loading" class="card p-8 text-center text-text-mute text-sm">加载模型配置中…</div>

    <div v-else class="flex flex-col gap-4">
      <article
        v-for="p in providers"
        :key="p.id || `unsaved-${providers.indexOf(p)}`"
        class="card p-4 sm:p-5"
        :class="{ 'provider-disabled': !p.enabled }"
      >
        <!-- 厂商标题行 -->
        <div class="flex flex-wrap items-center gap-2.5 mb-4">
          <span class="status-dot" :class="p.enabled ? (p.api_key_set || p.keyInput.trim() ? 'ok' : 'warn') : 'off'" aria-hidden="true"></span>
          <b class="text-[15px] font-bold truncate">{{ p.display_name || '（未命名厂商）' }}</b>
          <code class="font-mono text-[11px] px-1.5 py-0.5 bg-bg-2 border border-border text-text-mute">{{ p.id || '待填写标识' }}</code>
          <span v-if="p.builtin" class="chip !py-0.5 !px-2 !text-[10px]">内置</span>
          <span v-else class="chip !py-0.5 !px-2 !text-[10px]">自定义</span>
          <span
            class="text-[11px] font-mono"
            :class="(p.api_key_set || p.keyInput.trim()) ? 'text-green' : 'text-yellow'"
          >
            {{ keyStateText(p) }}
          </span>
          <label class="ml-auto flex items-center gap-2 text-[12px] text-text-dim cursor-pointer select-none">
            <input v-model="p.enabled" type="checkbox" class="accent-cyan w-3.5 h-3.5" />
            启用
          </label>
        </div>

        <!-- 基础字段 -->
        <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-[170px_minmax(160px,1fr)_minmax(220px,1.2fr)]">
          <label class="min-w-0">
            <span :class="labelClass">厂商标识</span>
            <input
              v-model="p.id"
              type="text"
              placeholder="如 my_relay"
              :disabled="p.saved"
              :title="p.saved ? '已保存的厂商标识不可修改' : '小写字母开头，仅小写字母/数字/下划线/连字符'"
              :class="inputClass"
              class="font-mono"
            />
          </label>
          <label class="min-w-0">
            <span :class="labelClass">显示名称</span>
            <input v-model="p.display_name" type="text" placeholder="如 我的 OpenAI 中转" :class="inputClass" />
          </label>
          <label class="min-w-0">
            <span :class="labelClass">Base URL（OpenAI 兼容）</span>
            <input
              v-model="p.base_url"
              type="text"
              placeholder="https://api.example.com/v1"
              :class="inputClass"
              class="font-mono"
              spellcheck="false"
            />
          </label>
        </div>

        <!-- API Key -->
        <div class="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-[minmax(240px,420px)_auto] lg:items-end">
          <label class="min-w-0">
            <span :class="labelClass"><PhKey :size="11" weight="bold" class="inline mr-1 -mt-0.5" aria-hidden="true" />API Key</span>
            <input
              v-model="p.keyInput"
              type="password"
              autocomplete="new-password"
              :placeholder="keyPlaceholder(p)"
              :class="inputClass"
              class="font-mono"
              spellcheck="false"
            />
          </label>
          <button
            v-if="p.api_key_source === 'file' && !p.keyInput.trim()"
            type="button"
            class="px-3 py-2 rounded-none text-[12px] font-semibold border transition-all self-end"
            :class="p.clearKey
              ? 'border-red bg-red/10 text-red'
              : 'border-border text-text-mute hover:text-text hover:border-text'"
            @click="clearFileKey(p)"
          >
            {{ p.clearKey ? '已标记清除（点击撤销）' : '清除已保存的 Key' }}
          </button>
        </div>

        <!-- 模型列表 -->
        <div class="mt-5 pt-4 border-t border-border">
          <div class="flex items-center justify-between gap-3 mb-3">
            <span :class="labelClass + ' !mb-0'">模型列表（ID + 显示名）</span>
            <button
              type="button"
              class="text-[12px] font-semibold text-cyan hover:underline inline-flex items-center gap-1"
              @click="addModel(p)"
            >
              <PhPlus :size="12" weight="bold" aria-hidden="true" /> 添加模型
            </button>
          </div>
          <div class="flex flex-col gap-2">
            <div
              v-for="(m, index) in p.models"
              :key="index"
              class="grid grid-cols-[minmax(150px,1.1fr)_minmax(120px,1fr)_32px] gap-2 items-center"
            >
              <input
                v-model="m.id"
                type="text"
                placeholder="模型 ID，如 deepseek-v4-pro"
                :class="inputClass + ' !py-2'"
                class="font-mono"
                spellcheck="false"
              />
              <input
                v-model="m.label"
                type="text"
                placeholder="显示名（可空）"
                :class="inputClass + ' !py-2'"
              />
              <button
                type="button"
                class="w-8 h-8 grid place-items-center border border-border text-text-mute hover:text-red hover:border-red/50 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                :title="`删除模型 ${m.id || '（空）'}`"
                :aria-label="`删除模型 ${m.id || '（空）'}`"
                :disabled="p.models.length <= 1"
                @click="removeModel(p, index)"
              >
                <PhX :size="13" weight="bold" aria-hidden="true" />
              </button>
            </div>
          </div>
        </div>

        <!-- 操作行 -->
        <div class="mt-4 pt-4 border-t border-border flex flex-wrap items-center gap-3">
          <button
            type="button"
            :disabled="testStates[p.id]?.running || !p.base_url.trim() || !p.id.trim()"
            class="px-3 py-1.5 rounded-none text-[12.5px] font-bold border border-cyan/50 text-cyan hover:bg-cyan/10 transition-all disabled:opacity-40 disabled:cursor-not-allowed inline-flex items-center gap-1.5"
            @click="runTest(p)"
          >
            <PhPlug :size="13" weight="bold" aria-hidden="true" />
            {{ testStates[p.id]?.running ? '测试中…' : '测试连接' }}
          </button>
          <span
            v-if="testStates[p.id] && !testStates[p.id].running"
            class="text-[12px]"
            :class="testStates[p.id].ok ? 'text-green' : 'text-red'"
          >
            {{ testStates[p.id].message }}
          </span>
          <button
            type="button"
            class="ml-auto px-3 py-1.5 rounded-none text-[12.5px] font-bold border border-red/40 text-red hover:bg-red/10 transition-all inline-flex items-center gap-1.5"
            @click="requestRemoveProvider(p)"
          >
            <PhTrash :size="13" weight="bold" aria-hidden="true" /> 删除厂商
          </button>
        </div>
      </article>
    </div>

    <ConfirmDialog
      :open="Boolean(confirmRequest)"
      :title="confirmRequest?.title || ''"
      :body="confirmRequest?.body || ''"
      :confirm-label="confirmRequest?.confirmLabel || '确认'"
      :tone="confirmRequest?.tone || 'accent'"
      @confirm="confirmRequest && (confirmRequest.action(), (confirmRequest = null))"
      @cancel="confirmRequest = null"
    />
  </div>
</template>

<style scoped>
.model-settings code { background: none; }
/* 厂商状态点：绿=已配置，黄=未配置 key，灰=停用 */
.status-dot { width: 8px; height: 8px; flex: 0 0 auto; border-radius: 50%; }
.status-dot.ok { background: rgb(var(--green)); box-shadow: 0 0 6px rgb(var(--green) / .5); }
.status-dot.warn { background: rgb(var(--yellow)); box-shadow: 0 0 6px rgb(var(--yellow) / .5); }
.status-dot.off { background: rgb(var(--text-mute) / .4); }
.provider-disabled { opacity: .62; }
.provider-disabled:hover { opacity: 1; }
</style>

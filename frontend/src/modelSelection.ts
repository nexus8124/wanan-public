import { computed, ref } from 'vue'
import { listModels, type ModelProfile } from './api/client'

const STORAGE_KEY = 'security-alert-selected-model'

export const modelProfiles = ref<ModelProfile[]>([])
export const selectedProvider = ref('deepseek')
export const selectedModel = ref('deepseek-v4-pro')
export const modelsLoading = ref(false)

let loadingPromise: Promise<void> | null = null

export const selectedProfile = computed(() =>
  modelProfiles.value.find((item) => item.provider === selectedProvider.value) || null,
)

export const selectedModelKey = computed(() =>
  `${selectedProvider.value}::${selectedModel.value}`,
)

export const selectedModelLabel = computed(() => {
  const profile = selectedProfile.value
  const model = profile?.models.find((item) => item.id === selectedModel.value)
  return model?.label || selectedModel.value
})

function selectionExists(provider: string, model: string, configuredOnly = false) {
  const profile = modelProfiles.value.find((item) => item.provider === provider)
  return Boolean(
    profile
      && (!configuredOnly || profile.configured)
      && profile.models.some((item) => item.id === model),
  )
}

function persistSelection() {
  if (typeof window !== 'undefined') {
    window.localStorage.setItem(STORAGE_KEY, selectedModelKey.value)
  }
}

export function selectModel(provider: string, model: string): boolean {
  if (!selectionExists(provider, model, true)) return false
  selectedProvider.value = provider
  selectedModel.value = model
  persistSelection()
  return true
}

export function selectModelKey(value: string): boolean {
  const separator = value.indexOf('::')
  if (separator < 1) return false
  return selectModel(value.slice(0, separator), value.slice(separator + 2))
}

export async function loadModelSelection(): Promise<void> {
  if (modelProfiles.value.length) return
  if (loadingPromise) return loadingPromise

  modelsLoading.value = true
  loadingPromise = (async () => {
    const data = await listModels()
    modelProfiles.value = data.providers

    const stored = typeof window !== 'undefined'
      ? window.localStorage.getItem(STORAGE_KEY) || ''
      : ''
    const separator = stored.indexOf('::')
    const storedProvider = separator > 0 ? stored.slice(0, separator) : ''
    const storedModel = separator > 0 ? stored.slice(separator + 2) : ''
    if (selectionExists(storedProvider, storedModel, true)) {
      selectedProvider.value = storedProvider
      selectedModel.value = storedModel
      return
    }

    const configured = data.providers.find((item) => item.configured)
    const initial = data.providers.find((item) => item.provider === 'deepseek' && item.configured)
      || configured
      || data.providers[0]
    if (!initial) return
    const preferred = initial.models.find((item) => item.id === initial.default_model)
      || initial.models[0]
    if (!preferred) return
    selectedProvider.value = initial.provider
    selectedModel.value = preferred.id
    if (initial.configured) persistSelection()
  })().finally(() => {
    modelsLoading.value = false
    loadingPromise = null
  })
  return loadingPromise
}

/** 配置页保存后调用：丢弃缓存的厂商目录，重新拉取并校正当前选择。 */
export async function reloadModelSelection(): Promise<void> {
  modelProfiles.value = []
  loadingPromise = null
  await loadModelSelection()
}

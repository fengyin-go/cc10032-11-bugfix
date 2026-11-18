/** CEP 命中台账接口：已消费窗口、合并清单、匹配写入与恢复核对。 */
import { request } from './client'

export type ConsumedWindow = {
  alert_id: number | null
  rule: string
  alert_rule: string
  signature: string
  pattern: string[]
  event_keys: string[]
  event_count: number
  start_ts: number
  end_ts: number
  sequence_index: number
  state: 'current' | 'merged' | string
  level: string
  status: string
  merged_into?: number | null
  created_at: number
}

export type ConsumedWindows = {
  ok: boolean
  rule: string | null
  windows: ConsumedWindow[]
  total_windows: number
  current_windows: number
  consumed_event_count: number
}

export type MergeEntry = {
  alert_id: number
  rule: string
  alert_rule: string
  signature: string
  pattern: string[]
  event_keys: string[]
  event_count: number
  start_ts: number
  end_ts: number
  sequence_index: number
  level: string
  status: string
  version: number
  restore_plan_id?: number | null
  overlaps_previous: boolean
  created_at: number
}

export type MergeList = {
  entries: MergeEntry[]
  total: number
  by_rule: Record<string, number>
  unique_event_count: number
  overlapping: { alert_id: number; rule: string; conflicts_with: number[]; event_keys: string[] }[]
  duplicate_free: boolean
  retention_policy: string
}

export type RetentionOption = {
  policy: string
  label: string
  effect: string
}

export type RestoreSyncCheck = {
  check: string
  ok: boolean
  detail: unknown
}

export type RestoreSyncReport = {
  ok: boolean
  plan_id: number
  plan: string
  rule: string
  alert_id: number | null
  alert_signature: string
  alert_event_keys: string[]
  alert_level: string
  alert_state: string
  checks: RestoreSyncCheck[]
  merge_list: MergeList
}

export type RestoreSyncResult = {
  ok: boolean
  checked: number
  plans: RestoreSyncReport[]
  merge_list?: MergeList
}

async function readJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await request(path, init)
  if (!response.ok) throw new Error(`接口返回 ${response.status}，数据未更新`)
  return (await response.json()) as T
}

export async function loadConsumedWindows(ruleName?: string): Promise<ConsumedWindows> {
  const query = ruleName ? `?rule_name=${encodeURIComponent(ruleName)}` : ''
  return readJson<ConsumedWindows>(`/api/cep_rule/consumed-windows${query}`)
}

export async function loadMergeList(ruleName?: string): Promise<{ ok: boolean; merge_list: MergeList; retention_options: RetentionOption[] }> {
  const query = ruleName ? `?rule_name=${encodeURIComponent(ruleName)}` : ''
  return readJson(`/api/alert_policy/cep-merge${query}`)
}

export async function matchEvents(
  ruleName: string,
  events: unknown[],
  alertRuleName?: string,
): Promise<{ ok: boolean; matches: number; created_alerts: number; reused_alerts: number; consumed_windows: ConsumedWindows }> {
  return readJson(`/api/cep_rule/${encodeURIComponent(ruleName)}/matches`, {
    method: 'POST',
    body: JSON.stringify({ events, alert_rule_name: alertRuleName }),
  })
}

export async function mergeAlerts(
  ruleName: string | undefined,
  policy: string,
): Promise<{ ok: boolean; retention_policy: string; merged_total: number; merge_list: MergeList }> {
  return readJson('/api/cep_rule/merge-alerts', {
    method: 'POST',
    body: JSON.stringify({ rule_name: ruleName, policy }),
  })
}

export async function loadRestoreSync(planId?: number): Promise<RestoreSyncResult> {
  const query = planId ? `?plan_id=${planId}` : ''
  return readJson<RestoreSyncResult>(`/api/restore_plan/alert-sync${query}`)
}

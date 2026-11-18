<template>
  <section class="ledger-panel" :data-testid="`ledger-${mode}`">
    <header class="ledger-head">
      <div>
        <h3>{{ title }}</h3>
        <p class="ledger-desc">{{ desc }}</p>
      </div>
      <div class="ledger-actions">
        <label v-if="mode === 'cep_rule' || mode === 'alert_policy'" class="ledger-field">
          <span>规则过滤</span>
          <input v-model="ruleFilter" data-testid="ledger-rule-filter" placeholder="留空表示全部" @change="reload" />
        </label>
        <button class="btn" data-testid="ledger-refresh" type="button" :disabled="loading" @click="reload">
          {{ loading ? '刷新中…' : '刷新核对' }}
        </button>
        <button
          v-if="mode === 'cep_rule'"
          class="btn primary"
          data-testid="ledger-merge-earliest"
          type="button"
          :disabled="loading"
          @click="runMerge('earliest_match')"
        >
          合并（保留最早命中）
        </button>
        <button
          v-if="mode === 'cep_rule'"
          class="btn"
          data-testid="ledger-merge-severity"
          type="button"
          :disabled="loading"
          @click="runMerge('severity')"
        >
          合并（保留最严重命中）
        </button>
      </div>
    </header>

    <p v-if="mergePolicyNote" class="ledger-note" data-testid="ledger-policy-note">{{ mergePolicyNote }}</p>
    <p v-if="errorMessage" class="error-text" data-testid="ledger-error">{{ errorMessage }}</p>

    <div class="stat-row ledger-stats">
      <article class="stat-card">
        <span class="stat-label">已消费窗口</span>
        <strong class="stat-value" data-testid="ledger-window-count">{{ windows.total_windows }}</strong>
        <small>当前版本 {{ windows.current_windows }}</small>
      </article>
      <article class="stat-card">
        <span class="stat-label">已消费事件</span>
        <strong class="stat-value" data-testid="ledger-consumed-events">{{ windows.consumed_event_count }}</strong>
        <small>跨窗口不重复</small>
      </article>
      <article class="stat-card">
        <span class="stat-label">合并清单条数</span>
        <strong class="stat-value" data-testid="ledger-merge-total">{{ mergeList.total }}</strong>
        <small>只含唯一当前命中</small>
      </article>
      <article class="stat-card">
        <span class="stat-label">重复事件</span>
        <strong class="stat-value" :class="{ 'ledger-bad': !mergeList.duplicate_free }" data-testid="ledger-duplicate-free">
          {{ mergeList.duplicate_free ? '0' : mergeList.overlapping.length }}
        </strong>
        <small>{{ mergeList.duplicate_free ? '无重复' : '存在重叠版本' }}</small>
      </article>
    </div>

    <template v-if="mode === 'cep_rule' || mode === 'alert_policy'">
      <h4 class="ledger-sub">告警合并清单（唯一当前命中）</h4>
      <table class="data-table" data-testid="ledger-merge-table">
        <thead>
          <tr>
            <th>告警ID</th>
            <th>规则</th>
            <th>事件序列</th>
            <th>事件数</th>
            <th>窗口起止</th>
            <th>级别</th>
            <th>状态</th>
            <th>恢复方案</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="entry in mergeList.entries" :key="entry.alert_id" :data-testid="`merge-row-${entry.alert_id}`">
            <td>{{ entry.alert_id }}</td>
            <td>{{ entry.rule }}</td>
            <td class="ledger-keys">{{ entry.event_keys.join(' → ') }}</td>
            <td>{{ entry.event_count }}</td>
            <td>{{ formatWindow(entry) }}</td>
            <td>{{ entry.level }}</td>
            <td>
              {{ entry.status }}
              <span v-if="entry.overlaps_previous" class="ledger-badge">重叠</span>
            </td>
            <td>{{ entry.restore_plan_id ?? '—' }}</td>
          </tr>
          <tr v-if="!mergeList.entries.length">
            <td colspan="8" class="empty-state">暂无 CEP 命中告警</td>
          </tr>
        </tbody>
      </table>

      <h4 class="ledger-sub">已消费窗口</h4>
      <table class="data-table" data-testid="ledger-window-table">
        <thead>
          <tr>
            <th>告警ID</th>
            <th>规则</th>
            <th>事件序列</th>
            <th>窗口起止</th>
            <th>版本状态</th>
            <th>合并去向</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="window in windows.windows" :key="`${window.alert_id}-${window.signature}`">
            <td>{{ window.alert_id ?? '—' }}</td>
            <td>{{ window.rule }}</td>
            <td class="ledger-keys">{{ window.event_keys.join(' → ') }}</td>
            <td>{{ formatWindow(window) }}</td>
            <td>{{ window.state === 'current' ? '当前版本' : '已合并' }}</td>
            <td>{{ window.merged_into ?? '—' }}</td>
          </tr>
          <tr v-if="!windows.windows.length">
            <td colspan="6" class="empty-state">暂无已消费窗口，先执行 CEP 匹配</td>
          </tr>
        </tbody>
      </table>
    </template>

    <template v-if="mode === 'restore_plan'">
      <h4 class="ledger-sub">恢复方案 → 保留告警 同步核对</h4>
      <table class="data-table" data-testid="ledger-restore-table">
        <thead>
          <tr>
            <th>方案ID</th>
            <th>方案名称</th>
            <th>引用告警</th>
            <th>告警状态</th>
            <th>事件序列</th>
            <th>在合并清单</th>
            <th>核对结果</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="report in sync.plans" :key="report.plan_id" :data-testid="`restore-row-${report.plan_id}`">
            <td>{{ report.plan_id }}</td>
            <td>{{ report.plan }}</td>
            <td>{{ report.alert_id ?? '—' }}</td>
            <td>{{ report.alert_state === 'current' ? '当前版本' : report.alert_state }}</td>
            <td class="ledger-keys">{{ report.alert_event_keys.join(' → ') || '—' }}</td>
            <td>{{ report.checks.find((c) => c.check === 'alert_in_merge_list')?.ok ? '是' : '否' }}</td>
            <td :class="report.ok ? 'ledger-ok' : 'ledger-bad'">
              {{ report.ok ? '一致' : '不一致' }}
            </td>
          </tr>
          <tr v-if="!sync.plans.length">
            <td colspan="7" class="empty-state">暂无关联 CEP 命中告警的恢复方案</td>
          </tr>
        </tbody>
      </table>
    </template>

    <details class="ledger-detail">
      <summary>合并取舍评估</summary>
      <ul>
        <li v-for="option in retentionOptions" :key="option.policy">
          <strong>{{ option.label }}</strong>（{{ option.policy }}）：{{ option.effect }}
        </li>
      </ul>
    </details>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import {
  loadConsumedWindows,
  loadMergeList,
  loadRestoreSync,
  mergeAlerts,
  type ConsumedWindows,
  type MergeList,
  type RestoreSyncResult,
  type RetentionOption,
} from '@/api/cep-ledger'

const props = defineProps<{ mode: 'cep_rule' | 'alert_policy' | 'restore_plan'; ruleName?: string }>()

const title = computed(() => {
  if (props.mode === 'cep_rule') return 'CEP 工作台：已消费窗口与告警合并清单'
  if (props.mode === 'alert_policy') return 'CEP 命中告警合并核对'
  return '故障恢复：告警引用同步核对'
})
const desc = computed(() => {
  if (props.mode === 'cep_rule') return '一次规则命中只占用一个已消费窗口；合并后只保留一个当前序列版本。'
  if (props.mode === 'alert_policy') return '合并清单只统计未被前序命中消费的事件，同一事件不会重复出现。'
  return '恢复方案只引用合并清单保留的那条告警，刷新后通过接口重新核对。'
})

const loading = ref(false)
const errorMessage = ref('')
const mergePolicyNote = ref('')
const ruleFilter = ref(props.ruleName ?? '')
const windows = ref<ConsumedWindows>({
  ok: true,
  rule: null,
  windows: [],
  total_windows: 0,
  current_windows: 0,
  consumed_event_count: 0,
})
const mergeList = ref<MergeList>({
  entries: [],
  total: 0,
  by_rule: {},
  unique_event_count: 0,
  overlapping: [],
  duplicate_free: true,
  retention_policy: 'earliest_match',
})
const retentionOptions = ref<RetentionOption[]>([])
const sync = ref<RestoreSyncResult>({ ok: true, checked: 0, plans: [] })

function activeRule(): string | undefined {
  const value = ruleFilter.value.trim()
  return value ? value : undefined
}

function formatWindow(row: { start_ts: number; end_ts: number }): string {
  if (!row.start_ts) return '—'
  return `${row.start_ts.toFixed(1)} → ${row.end_ts.toFixed(1)}`
}

async function reload() {
  loading.value = true
  errorMessage.value = ''
  try {
    if (props.mode === 'restore_plan') {
      const [syncResult, mergeResult] = await Promise.all([
        loadRestoreSync(),
        loadMergeList(),
      ])
      sync.value = syncResult
      mergeList.value = mergeResult.merge_list
      retentionOptions.value = mergeResult.retention_options
      windows.value = await loadConsumedWindows()
    } else {
      const [windowResult, mergeResult] = await Promise.all([
        loadConsumedWindows(activeRule()),
        loadMergeList(activeRule()),
      ])
      windows.value = windowResult
      mergeList.value = mergeResult.merge_list
      retentionOptions.value = mergeResult.retention_options
    }
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '台账读取失败'
  } finally {
    loading.value = false
  }
}

async function runMerge(policy: string) {
  loading.value = true
  errorMessage.value = ''
  try {
    const result = await mergeAlerts(activeRule(), policy)
    mergePolicyNote.value =
      `已按「${policy}」合并 ${result.merged_total} 条重叠命中，保留 ${result.merge_list.total} 条当前版本。`
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '合并失败'
  } finally {
    loading.value = false
  }
}

onMounted(reload)
</script>

<style scoped>
.ledger-panel {
  margin-top: 16px;
  padding: 14px 16px;
  background: #fff;
  border: 1px solid var(--border);
  border-radius: 8px;
}
.ledger-head { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; }
.ledger-head h3 { margin: 0 0 4px; font-size: 15px; }
.ledger-desc { margin: 0; color: var(--muted); font-size: 12px; }
.ledger-actions { display: flex; gap: 8px; align-items: flex-end; flex-wrap: wrap; }
.ledger-field { display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--muted); }
.ledger-field input { border: 1px solid var(--border); border-radius: 6px; padding: 5px 8px; }
.ledger-stats { margin-top: 12px; }
.ledger-stats small { color: var(--muted); font-size: 11px; }
.ledger-sub { margin: 16px 0 6px; font-size: 13px; }
.ledger-keys { font-family: monospace; font-size: 12px; }
.ledger-badge { margin-left: 6px; padding: 1px 6px; border-radius: 10px; background: #fde2e1; color: #b42318; font-size: 11px; }
.ledger-ok { color: #15803d; }
.ledger-bad { color: #b42318; }
.ledger-note { margin: 8px 0 0; color: #15803d; font-size: 12px; }
.ledger-detail { margin-top: 14px; font-size: 12px; color: var(--muted); }
.ledger-detail ul { margin: 6px 0 0; padding-left: 18px; }
</style>

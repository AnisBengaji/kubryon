// Chart.js instances are kept OUTSIDE Alpine's reactive data object on
// purpose -- Alpine wraps x-data properties in Proxies, and Chart.js
// internals don't play well with that. These live at module scope and
// are updated (not recreated) on every refresh.
let chartTimeline = null;
let chartActions = null;
let chartRules = null;

const CHART_COLORS = {
  accent: '#4c8dff', danger: '#f0666e', warning: '#d9a441',
  success: '#3fb968', purple: '#9f7aea', text3: '#6b6e76',
};

function baseChartOptions(extra) {
  return Object.assign({
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#1c1f24',
        borderColor: '#34363d',
        borderWidth: 1,
        titleColor: '#e7e8ea',
        bodyColor: '#9a9ea6',
        padding: 8,
        titleFont: { family: 'Inter', size: 11 },
        bodyFont: { family: 'JetBrains Mono', size: 11 },
      },
    },
    scales: {
      x: { grid: { color: '#1c1f24' }, ticks: { color: '#6b6e76', font: { size: 10 } } },
      y: { grid: { color: '#1c1f24' }, ticks: { color: '#6b6e76', font: { size: 10 } }, beginAtZero: true },
    },
  }, extra || {});
}

function buildTimelineBuckets(incidents) {
  const now = Date.now();
  const bucketMs = 5 * 60 * 1000;
  const labels = [];
  const values = new Array(12).fill(0);
  for (let i = 11; i >= 0; i--) {
    const t = new Date(now - i * bucketMs);
    labels.push(t.getHours().toString().padStart(2, '0') + ':' + t.getMinutes().toString().padStart(2, '0'));
  }
  incidents.forEach(inc => {
    if (!inc.timestamp) return;
    const age = now - new Date(inc.timestamp).getTime();
    if (age < 0 || age > bucketMs * 12) return;
    const idx = 11 - Math.floor(age / bucketMs);
    if (idx >= 0 && idx < 12) values[idx]++;
  });
  return { labels, values };
}

function initCharts() {
  const ctxTimeline = document.getElementById('chart-timeline');
  const ctxActions = document.getElementById('chart-actions');
  const ctxRules = document.getElementById('chart-rules');
  if (!ctxTimeline || chartTimeline) return; // already initialized or DOM not ready

  chartTimeline = new Chart(ctxTimeline, {
    type: 'line',
    data: { labels: [], datasets: [{
      data: [], borderColor: CHART_COLORS.accent, backgroundColor: 'rgba(76,141,255,.12)',
      fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5,
    }]},
    options: baseChartOptions(),
  });

  chartActions = new Chart(ctxActions, {
    type: 'doughnut',
    data: {
      labels: ['Killed', 'Isolated', 'Breaker blocked', 'Resource'],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: [CHART_COLORS.danger, CHART_COLORS.warning, CHART_COLORS.purple, CHART_COLORS.success],
        borderColor: '#16181c', borderWidth: 2,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '68%',
      plugins: {
        legend: { position: 'bottom', labels: { color: '#9a9ea6', font: { family: 'Inter', size: 11 }, boxWidth: 10, padding: 12 } },
        tooltip: baseChartOptions().plugins.tooltip,
      },
    },
  });

  chartRules = new Chart(ctxRules, {
    type: 'bar',
    data: { labels: [], datasets: [{ data: [], backgroundColor: CHART_COLORS.accent, borderRadius: 3, barThickness: 14 }] },
    options: baseChartOptions({
      indexAxis: 'y',
      scales: {
        x: { grid: { color: '#1c1f24' }, ticks: { color: '#6b6e76', font: { size: 10 } }, beginAtZero: true },
        y: { grid: { display: false }, ticks: { color: '#9a9ea6', font: { family: 'JetBrains Mono', size: 10 } } },
      },
    }),
  });
}

function updateCharts(incidents, stats) {
  if (!chartTimeline) return;

  const { labels, values } = buildTimelineBuckets(incidents);
  chartTimeline.data.labels = labels;
  chartTimeline.data.datasets[0].data = values;
  chartTimeline.update('none');

  chartActions.data.datasets[0].data = [
    stats.killed || 0, stats.isolated || 0, stats.circuit_breaker_blocks || 0, stats.resource_alerts || 0,
  ];
  chartActions.update('none');

  const topRules = (stats.top_rules || []).slice(0, 8);
  chartRules.data.labels = topRules.map(r => r.rule.length > 30 ? r.rule.slice(0, 28) + '…' : r.rule);
  chartRules.data.datasets[0].data = topRules.map(r => r.count);
  chartRules.update('none');
}

function badgeColor(action) {
  if (!action) return '#d9a441';
  if (action.includes('circuit_breaker')) return '#9f7aea';
  if (action.startsWith('kill')) return '#f0666e';
  if (action.startsWith('isolate')) return '#d9a441';
  if (action === 'resource_alert') return '#3fb968';
  return '#d9a441';
}

function badgeLabel(action) {
  const map = {
    kill: 'Kill', isolate: 'Isolate', resource_alert: 'Resource alert',
    kill_blocked_circuit_breaker: 'Breaker blocked', isolate_blocked_circuit_breaker: 'Breaker blocked',
    kill_skipped_already_done: 'Already killed', isolate_skipped_already_done: 'Isolate (dup)',
  };
  return map[action] || (action || '').replace(/_/g, ' ');
}

function timeAgo(iso) {
  if (!iso) return '';
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 0) return new Date(iso).toLocaleTimeString();
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  return Math.floor(s / 3600) + 'h ago';
}

function incidentsApp() {
  return {
    incidents: [],
    stats: {},
    filter: 'all',
    search: '',
    statCards: [
      { key: 'total_events', label: 'Total events', color: '#4c8dff' },
      { key: 'killed', label: 'Pods killed', color: '#f0666e' },
      { key: 'isolated', label: 'Pods isolated', color: '#d9a441' },
      { key: 'circuit_breaker_blocks', label: 'Breaker blocks', color: '#9f7aea' },
      { key: 'resource_alerts', label: 'Resource alerts', color: '#3fb968' },
      { key: 'pods_affected', label: 'Pods affected', color: '#6b6e76' },
    ],
    filters: [
      { key: 'all', label: 'All', test: () => true },
      { key: 'kill', label: 'Killed', test: i => i.action === 'kill' },
      { key: 'isolate', label: 'Isolated', test: i => i.action === 'isolate' },
      { key: 'blocked', label: 'Breaker blocked', test: i => (i.action || '').includes('circuit_breaker') },
      { key: 'resource_alert', label: 'Resource', test: i => i.action === 'resource_alert' },
      { key: 'review', label: 'Needs review', test: i => i.verified === false },
    ],

    get filteredIncidents() {
      const f = this.filters.find(x => x.key === this.filter) || this.filters[0];
      const q = this.search.trim().toLowerCase();
      return this.incidents.filter(i => {
        if (!f.test(i)) return false;
        if (!q) return true;
        const hay = [i.pod_name, i.namespace, i.triggering_rule, i.action].filter(Boolean).join(' ').toLowerCase();
        return hay.includes(q);
      });
    },

    badgeColor, badgeLabel, timeAgo,

    async init() {
      window.addEventListener('rc:search', (e) => { this.search = e.detail; });
      await this.refresh();
      initCharts();
      updateCharts(this.incidents, this.stats);
      setInterval(() => this.refresh().then(() => updateCharts(this.incidents, this.stats)), 5000);
    },

    async refresh() {
      try {
        const res = await fetch('/api/incidents');
        const data = await res.json();
        this.incidents = data.incidents || [];
        this.stats = data.stats || {};
        window.dispatchEvent(new CustomEvent('rc:connok'));
      } catch (e) {
        window.dispatchEvent(new CustomEvent('rc:connlost'));
      }
    },
  };
}

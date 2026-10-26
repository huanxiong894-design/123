'use strict';

/* 2026 羊城杯编排看板前端：WebSocket hello 快照 + 增量事件。所有内容以 textContent 渲染，防 XSS。 */

const STATUS = {
  DISCOVERED: { label: '已发现', cls: 'st-DISCOVERED' },
  PREPARING: { label: '准备中', cls: 'st-PREPARING' },
  READY: { label: '就绪', cls: 'st-READY' },
  SOLVING: { label: '解题中', cls: 'st-SOLVING' },
  SOLVED: { label: '已解出', cls: 'st-SOLVED' },
  SUBMITTING: { label: '提交中', cls: 'st-SUBMITTING' },
  SUBMITTED: { label: '已提交', cls: 'st-SUBMITTED' },
  PAUSED: { label: '已暂停', cls: 'st-PAUSED' },
  STOPPED: { label: '已停止', cls: 'st-STOPPED' },
  FAILED: { label: '失败', cls: 'st-FAILED' },
  NEEDS_HUMAN: { label: '需人工', cls: 'st-NEEDS_HUMAN' },
};

const FILTERS = {
  all: () => true,
  running: (s) => ['PREPARING', 'READY', 'SOLVING', 'SUBMITTING'].includes(s),
  attention: (s) => ['NEEDS_HUMAN', 'PAUSED'].includes(s),
  failed: (s) => ['FAILED', 'STOPPED'].includes(s),
  solved: (s) => ['SOLVED', 'SUBMITTING', 'SUBMITTED'].includes(s),
};

const MAX_EVENTS = 3000;
const SKIP_TYPES = new Set(['heartbeat', 'pong', 'discovery.tick', 'event.dropped']);

const state = {
  overview: null,
  challenges: new Map(),
  selectedId: null,
  events: [],
  filter: 'all',
  scope: null,
  ws: null,
  lastSeq: 0,
  helloReceived: false,
  reconnectDelay: 1000,
  forceReset: false,
  clockOffset: 0,
  detailCache: new Map(),
  stopAllArmed: false,
};

let toastTimer = null;
let stopAllTimer = null;

const $ = (id) => document.getElementById(id);

/* ------------------------------------------------------------------ utils */
function pad(n) {
  return String(n).padStart(2, '0');
}

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function setText(id, value) {
  const node = $(id);
  if (node) node.textContent = String(value);
}

function truncate(text, limit) {
  const value = String(text ?? '');
  return value.length > limit ? value.slice(0, limit) + `…（截断 ${value.length - limit} 字）` : value;
}

function fmtTime(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '--:--:--';
  return date.toLocaleTimeString('zh-CN', { hour12: false });
}

function fmtDateTime(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '--';
  return date.toLocaleString('zh-CN', {
    hour12: false,
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function fmtDuration(ms) {
  if (!Number.isFinite(ms) || ms < 0) return '--';
  const total = Math.floor(ms / 1000);
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  if (days > 0) return `${days}d${hours}h`;
  if (hours > 0) return `${hours}h${pad(minutes)}m`;
  if (minutes > 0) return `${minutes}m${pad(seconds)}s`;
  return `${seconds}s`;
}

function fmtClock(ms) {
  let total = Math.max(0, Math.floor(ms / 1000));
  const days = Math.floor(total / 86400);
  total -= days * 86400;
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  const clock = `${pad(hours)}:${pad(minutes)}:${pad(seconds)}`;
  return days > 0 ? `${days}天 ${clock}` : clock;
}

function statusInfo(status) {
  return STATUS[status] || { label: status || '未知', cls: 'st-DISCOVERED' };
}

function challengeLabel(id) {
  const challenge = state.challenges.get(Number(id));
  if (!challenge) return id == null ? '' : `#${id}`;
  return `#${pad(challenge.seq_no ?? challenge.id)} ${challenge.title}`;
}

function showToast(message, kind) {
  const toast = $('toast');
  toast.textContent = String(message);
  toast.className = 'toast' + (kind === true ? ' err' : kind === 'ok' ? ' ok' : '');
  toast.classList.remove('hidden');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.add('hidden'), 4500);
}

async function readError(resp) {
  try {
    const data = await resp.json();
    const detail = data.detail ?? data.error ?? data;
    return typeof detail === 'string' ? detail : JSON.stringify(detail);
  } catch (err) {
    return `HTTP ${resp.status}`;
  }
}

async function getJSON(url) {
  const resp = await fetch(url, { headers: { Accept: 'application/json' } });
  if (!resp.ok) throw new Error(await readError(resp));
  return resp.json();
}

async function postJSON(url, body) {
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: body === undefined ? null : JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(await readError(resp));
  return resp.json();
}

/* ------------------------------------------------------------------ overview */
function applyOverview(overview) {
  if (!overview) return;
  state.overview = overview;
  const serverTime = Date.parse(overview.server_time);
  if (!Number.isNaN(serverTime)) state.clockOffset = serverTime - Date.now();
  renderStats();
  renderBadges();
}

function computeCounts() {
  const counts = {};
  for (const challenge of state.challenges.values()) {
    counts[challenge.status] = (counts[challenge.status] || 0) + 1;
  }
  return counts;
}

function renderStats() {
  const overview = state.overview || {};
  const counts = overview.counts || computeCounts();
  const sum = (keys) => keys.reduce((acc, key) => acc + (counts[key] || 0), 0);
  const total = overview.total ?? Object.values(counts).reduce((a, b) => a + b, 0);
  setText('stat-total', total);
  setText('stat-running', overview.running ?? sum(['PREPARING', 'READY', 'SOLVING', 'SUBMITTING']));
  setText('stat-solved', overview.solved ?? sum(['SOLVED', 'SUBMITTING', 'SUBMITTED']));
  setText('stat-submitted', overview.submitted ?? sum(['SUBMITTED']));
  setText('stat-attention', overview.attention ?? sum(['NEEDS_HUMAN', 'PAUSED']));
  setText('stat-failed', overview.failed ?? sum(['FAILED']));
  const submissions = overview.submissions || {};
  setText('stat-submits', `${submissions.live ?? 0}/${overview.max_auto_submits ?? '—'}`);
  const discovery = overview.discovery || {};
  setText('stat-discovery', discoveryText(discovery));
}

function discoveryText(discovery) {
  const labels = {
    idle: '空闲',
    running: '轮询中',
    logging_in: '登录中',
    error: '异常',
    disabled: '已禁用',
    stopped: '已停止',
  };
  const label = labels[discovery.state] || discovery.state || '未知';
  return discovery.ticks ? `${label} · ${discovery.ticks}` : label;
}

function renderBadges() {
  const overview = state.overview || {};
  const features = overview.features || {};
  $('dryrun-badge').classList.toggle('hidden', !overview.dry_run);

  const session = overview.session || {};
  const discovery = overview.discovery || {};
  let sessionState = session.state || 'unknown';
  if (discovery.state === 'logging_in') sessionState = 'logging_in';
  if (discovery.state === 'error' && sessionState !== 'logged_in') sessionState = 'error';
  const meta = {
    logged_in: ['已登录', 'ok'],
    logged_out: ['未登录', 'warn'],
    logging_in: ['登录中', 'warn'],
    needs_human: ['需人工', 'err'],
    error: ['异常', 'err'],
    unknown: ['会话未知', ''],
  }[sessionState] || [sessionState, ''];
  setText('session-text', `平台 ${meta[0]}`);
  $('session-dot').className = `dot ${meta[1]}`.trim();
  $('session-badge').title = session.detail || '平台登录会话';
}

function updateCountdown() {
  const overview = state.overview;
  if (!overview || !overview.schedule) return;
  const now = Date.now() + state.clockOffset;
  const start = Date.parse(overview.schedule.start);
  const end = Date.parse(overview.schedule.end);
  if (Number.isNaN(start) || Number.isNaN(end)) return;
  if (now < start) {
    setText('countdown-label', '距开赛');
    setText('countdown-value', fmtClock(start - now));
  } else if (now < end) {
    setText('countdown-label', '距结束');
    setText('countdown-value', fmtClock(end - now));
  } else {
    setText('countdown-label', '比赛');
    setText('countdown-value', '已结束');
  }
}

/* ------------------------------------------------------------------ challenges */
function sortedChallenges() {
  return [...state.challenges.values()].sort(
    (a, b) => (a.seq_no ?? a.id ?? 0) - (b.seq_no ?? b.id ?? 0)
  );
}

function applyChallenges(list) {
  const next = new Map();
  for (const challenge of list || []) {
    if (challenge && challenge.id != null) next.set(Number(challenge.id), challenge);
  }
  state.challenges = next;
  if (state.selectedId != null && !next.has(state.selectedId)) {
    state.selectedId = null;
    state.scope = null;
    $('btn-scope-all').classList.add('hidden');
  }
  if (state.scope != null && !next.has(state.scope)) {
    state.scope = null;
    $('btn-scope-all').classList.add('hidden');
  }
  if (state.selectedId == null && next.size > 0) {
    const first = sortedChallenges()[0];
    state.selectedId = first.id;
    loadDetail(first.id);
  }
  renderChallengeList();
  renderDetail();
  renderTimeline();
  updateActions();
}

function upsertChallenge(challenge) {
  if (!challenge || challenge.id == null) return;
  const id = Number(challenge.id);
  state.challenges.set(id, challenge);
  renderChallengeList();
  if (state.selectedId === id) renderDetail();
}

function renderChallengeList() {
  const box = $('challenge-list');
  box.textContent = '';
  const all = sortedChallenges();
  const visible = all.filter((challenge) => FILTERS[state.filter](challenge.status));
  setText('list-count', visible.length === all.length ? all.length : `${visible.length}/${all.length}`);
  if (visible.length === 0) {
    box.appendChild(el('div', 'empty', all.length ? '当前筛选下没有题目' : '等待发现题目…'));
    return;
  }
  for (const challenge of visible) {
    const row = el(
      'div',
      'challenge-row' + (challenge.id === state.selectedId ? ' selected' : '')
    );
    row.tabIndex = 0;
    row.setAttribute('role', 'listitem');
    row.dataset.id = String(challenge.id);
    row.appendChild(el('div', 'seq', pad(challenge.seq_no ?? challenge.id)));
    const main = el('div', 'row-main');
    const top = el('div', 'row-top');
    top.appendChild(el('span', 'challenge-title', challenge.title));
    const info = statusInfo(challenge.status);
    top.appendChild(el('span', `pill ${info.cls}`, info.label));
    main.appendChild(top);
    const meta = el('div', 'row-meta');
    meta.appendChild(el('span', 'cat', challenge.category || 'misc'));
    meta.appendChild(el('span', 'score', challenge.score == null ? '-' : challenge.score));
    if (challenge.container_available) meta.appendChild(el('span', 'muted', '靶机'));
    const discovered = Date.parse(challenge.discovered_at);
    if (!Number.isNaN(discovered)) {
      meta.appendChild(el('span', 'muted', fmtDuration(Date.now() + state.clockOffset - discovered)));
    }
    main.appendChild(meta);
    row.appendChild(main);
    row.addEventListener('click', () => selectChallenge(challenge.id));
    row.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        selectChallenge(challenge.id);
      }
    });
    box.appendChild(row);
  }
}

function selectChallenge(id) {
  state.selectedId = Number(id);
  state.scope = Number(id);
  $('btn-scope-all').classList.remove('hidden');
  renderChallengeList();
  renderDetail();
  renderTimeline();
  updateActions();
  loadDetail(id);
}

async function loadDetail(id) {
  const numeric = Number(id);
  try {
    const data = await getJSON(`/api/challenges/${numeric}`);
    state.detailCache.set(numeric, data);
    if (data.challenge) upsertChallenge(data.challenge);
    if (state.selectedId === numeric) renderDetail();
  } catch (err) {
    showToast(`加载题目详情失败：${err.message}`, true);
  }
}

/* ------------------------------------------------------------------ detail */
function addMeta(dl, key, value) {
  dl.appendChild(el('dt', null, key));
  dl.appendChild(el('dd', null, value));
}

function renderDetail() {
  const box = $('detail');
  box.textContent = '';
  const challenge = state.challenges.get(state.selectedId);
  setText('detail-status', challenge ? statusInfo(challenge.status).label : '');
  if (!challenge) {
    box.appendChild(el('div', 'empty', '从左侧选择一道题…'));
    return;
  }

  box.appendChild(el('h2', 'detail-title', challenge.title));
  const sub = el('div', 'detail-sub');
  const info = statusInfo(challenge.status);
  sub.appendChild(el('span', `pill ${info.cls}`, info.label));
  sub.appendChild(el('span', 'cat', challenge.category || 'misc'));
  sub.appendChild(el('span', 'score', `${challenge.score == null ? '-' : challenge.score} 分`));
  box.appendChild(sub);

  const dl = el('dl', 'meta-grid');
  addMeta(dl, '题号', `#${pad(challenge.seq_no ?? challenge.id)}`);
  addMeta(dl, '平台 ID', challenge.platform_id || '-');
  addMeta(dl, 'UID', challenge.uid || '-');
  addMeta(dl, '发现时间', fmtDateTime(challenge.discovered_at));
  addMeta(dl, '工作区', challenge.workspace || '（尚未创建）');
  const target = challenge.target
    ? challenge.target.address || `${challenge.target.host || ''}:${challenge.target.port || ''}`
    : challenge.container_available
      ? '未启动（可自动启动）'
      : '无';
  addMeta(dl, '靶机', target);
  box.appendChild(dl);

  if (challenge.workspace) {
    const row = el('div', 'copy-row');
    const button = el('button', 'copy-btn', '复制工作区路径');
    button.type = 'button';
    button.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(challenge.workspace);
        showToast('已复制工作区路径', 'ok');
      } catch (err) {
        showToast(challenge.workspace, 'ok');
      }
    });
    row.appendChild(button);
    box.appendChild(row);
  }

  const descSection = el('div', 'section');
  descSection.appendChild(el('h3', null, '题目说明'));
  descSection.appendChild(
    el('pre', 'desc', challenge.description_md || '（平台未提供文字说明，请查看附件/靶机）')
  );
  box.appendChild(descSection);

  const attachments = el('div', 'section');
  attachments.appendChild(el('h3', null, '附件'));
  const attList = el('ul', 'kv-list');
  if (challenge.attachments && challenge.attachments.length) {
    for (const attachment of challenge.attachments) {
      const li = el('li');
      li.appendChild(el('code', null, attachment.name));
      const size = attachment.size == null ? '' : ` · ${attachment.size} B`;
      const sha = attachment.sha256 ? ` · sha256 ${attachment.sha256.slice(0, 12)}…` : '';
      li.appendChild(document.createTextNode(size + sha));
      attList.appendChild(li);
    }
  } else {
    attList.appendChild(el('li', 'muted', '（无附件）'));
  }
  attachments.appendChild(attList);
  if (challenge.container_available) {
    attachments.appendChild(
      el('div', 'notice', '容器题：平台提供容器按钮时可直接启动；mock 平台可在详情页手动启动，地址会写入 target 字段。')
    );
  }
  box.appendChild(attachments);

  const detail = state.detailCache.get(challenge.id) || {};

  const messagesSection = el('div', 'section');
  messagesSection.appendChild(el('h3', null, '操作员 / Agent 消息'));
  const messages = el('ul', 'kv-list');
  if (detail.messages && detail.messages.length) {
    for (const message of detail.messages) {
      const li = el('li');
      li.appendChild(el('span', 'when', `${fmtDateTime(message.created_at)} `));
      const who = message.direction === 'operator' ? '操作员' : message.direction === 'agent' ? 'Agent' : '系统';
      li.appendChild(el('span', 'who', who));
      li.appendChild(
        document.createTextNode(`：${message.content}${message.delivered ? '' : '（未送达）'}`)
      );
      messages.appendChild(li);
    }
  } else {
    messages.appendChild(el('li', 'muted', '暂无消息'));
  }
  messagesSection.appendChild(messages);
  box.appendChild(messagesSection);

  const submissionsSection = el('div', 'section');
  submissionsSection.appendChild(el('h3', null, '提交记录'));
  const submissions = el('ul', 'kv-list');
  if (detail.submissions && detail.submissions.length) {
    for (const submission of detail.submissions) {
      const li = el('li');
      li.appendChild(el('span', 'when', `${fmtDateTime(submission.created_at)} `));
      li.appendChild(el('code', null, submission.flag || submission.flag_masked || '***'));
      li.appendChild(document.createTextNode(` · ${submission.status} · ${submission.message || ''}`));
      submissions.appendChild(li);
    }
  } else {
    submissions.appendChild(el('li', 'muted', '暂无提交（检测到合法 flag.txt 后产生）'));
  }
  submissionsSection.appendChild(submissions);
  box.appendChild(submissionsSection);

  const runsSection = el('div', 'section');
  runsSection.appendChild(el('h3', null, 'Agent runs'));
  const runs = el('ul', 'kv-list');
  if (detail.runs && detail.runs.length) {
    for (const run of detail.runs) {
      const li = el('li');
      li.appendChild(el('code', null, `#${run.id}`));
      li.appendChild(document.createTextNode(` · ${run.backend} · ${run.status} · ${fmtDateTime(run.started_at)}`));
      runs.appendChild(li);
    }
  } else {
    runs.appendChild(el('li', 'muted', '暂无 run（Agent 尚未启动）'));
  }
  runsSection.appendChild(runs);
  box.appendChild(runsSection);

  box.appendChild(
    el(
      'div',
      'notice',
      'FlagWatcher 轮询 flag.txt，稳定且校验通过后自动入队提交（dry_run=true 时只记录）。accepted/already_solved 会停止 Agent；unknown 只复查平台状态并转人工，绝不盲目重试。'
    )
  );
}

/* ------------------------------------------------------------------ timeline */
function describeEvent(event) {
  const payload = event.payload || {};
  const name = event.challenge_id != null ? challengeLabel(event.challenge_id) : '';
  switch (event.type) {
    case 'system.ready':
      return {
        label: '系统',
        body: `看板启动 · v${payload.version || ''} · 平台 ${payload.adapter || ''}`,
        cls: 'ev-system',
      };
    case 'system.stopping':
      return { label: '系统', body: '看板正在关闭', cls: 'ev-system' };
    case 'challenge.discovered': {
      const challenge = payload.challenge || {};
      return {
        label: '新题',
        body:
          `${challenge.title || ''} · ${challenge.category || 'misc'} · ` +
          `${challenge.score == null ? '-' : challenge.score} 分\n` +
          `工作区：${challenge.workspace || ''}`,
        cls: 'ev-discovery',
      };
    }
    case 'challenge.updated':
      return { label: '更新', body: `${name} 平台信息已更新`, cls: 'ev-discovery' };
    case 'status.changed':
      return {
        label: '状态',
        body: `${name}：${payload.previous || '?'} → ${payload.status || '?'}`,
        cls: 'ev-discovery',
      };
    case 'operator.message':
      return {
        label: '操作员',
        body: `${payload.content || ''}${
          payload.delivered ? '' : `\n（未投递：${payload.reason || 'Agent 未运行'}）`
        }`,
        cls: 'ev-operator',
      };
    case 'operator.command':
      return { label: '指令', body: JSON.stringify(payload), cls: 'ev-operator' };
    case 'platform.state': {
      const session = payload.session || {};
      return {
        label: '平台',
        body: `会话 ${session.state || '?'}${session.detail ? ' · ' + session.detail : ''}`,
        cls: 'ev-platform',
      };
    }
    case 'alert':
      return {
        label: payload.level === 'error' ? '告警' : '提示',
        body: payload.message || '',
        cls: 'ev-alert',
      };
    case 'container.ready':
      return {
        label: '容器',
        body: `靶机就绪：${(payload.target && (payload.target.address || `${payload.target.host}:${payload.target.port}`)) || ''}`,
        cls: 'ev-platform',
      };
    case 'agent.text':
      return { label: 'Agent', body: truncate(payload.text, 2400), cls: 'ev-agent' };
    case 'agent.thinking':
      return { label: '思考', body: truncate(payload.text || '…', 1200), cls: 'ev-agent' };
    case 'agent.tool_use': {
      let input = payload.input;
      if (input && typeof input !== 'string') input = JSON.stringify(input);
      return {
        label: '工具',
        body: `${payload.name || 'tool'} ${truncate(input || '', 900)}`,
        cls: 'ev-agent',
      };
    }
    case 'agent.tool_result':
      return {
        label: '结果',
        body: truncate(payload.output || payload.text || '', 1200),
        cls: 'ev-agent',
      };
    case 'agent.result':
      return { label: '完成', body: truncate(payload.text || '(no result)', 2000), cls: 'ev-agent' };
    case 'agent.init':
      return {
        label: '启动',
        body: `模型 ${payload.model || '?'} · session ${payload.session_id || '?'}${
          payload.tools ? ` · ${payload.tools} 个工具` : ''
        }`,
        cls: 'ev-agent',
      };
    case 'agent.notice':
      return { label: 'Agent 提示', body: truncate(payload.text || payload.message || '', 1200), cls: 'ev-agent' };
    case 'agent.stalled':
      return {
        label: '停滞',
        body: `已 ${payload.seconds || '?'}s 无输出 · ${payload.action || ''}`,
        cls: 'ev-alert',
      };
    case 'flag.detected':
      return {
        label: 'Flag',
        body: `${payload.flag_masked || '***'}${payload.sha256 ? `\nsha256：${payload.sha256}` : ''}`,
        cls: 'ev-submit',
      };
    case 'agent.error':
      return { label: 'Agent 错误', body: truncate(payload.message || payload.error || '', 1200), cls: 'ev-alert' };
    case 'agent.exited':
      return {
        label: '退出',
        body: `退出码 ${payload.code == null ? '?' : payload.code}${payload.signal ? ' · ' + payload.signal : ''}`,
        cls: 'ev-agent',
      };
    case 'run.started':
      return {
        label: 'Run',
        body: `run #${event.run_id} 启动（${payload.backend || ''} · pid ${payload.pid || '?'}${
          payload.resume ? ' · resume' : ''
        }）`,
        cls: 'ev-agent',
      };
    case 'run.exited':
      return { label: 'Run', body: `run #${event.run_id} 结束：${payload.status || ''}`, cls: 'ev-agent' };
    case 'submit.queued':
      return {
        label: '入队',
        body: `${payload.flag_masked || '***'}${payload.manual ? ' · 手动' : ''}${
          payload.submission_id ? ` · #${payload.submission_id}` : ''
        }`,
        cls: 'ev-submit',
      };
    case 'submit.retry':
      return {
        label: '提交重试',
        body: `${payload.status || ''} · ${payload.message || ''} · ${
          payload.retry_in_seconds == null ? '?' : payload.retry_in_seconds
        }s 后重试（第 ${payload.attempt || '?'} 次）`,
        cls: 'ev-alert',
      };
    case 'submit.result': {
      const ok = ['accepted', 'already_solved', 'dry_run'].includes(payload.status);
      return {
        label: '提交结果',
        body: `${payload.status || ''} ${payload.message || ''}`.trim(),
        cls: ok ? 'ev-submit' : 'ev-alert',
      };
    }
    default:
      return {
        label: event.type,
        body: truncate(JSON.stringify(payload), 900),
        cls: 'ev-other',
      };
  }
}

function buildEntry(event) {
  const desc = describeEvent(event);
  if (!desc) return null;
  const entry = el('div', `entry ${desc.cls || ''}`.trim());
  entry.appendChild(el('div', 'entry-time', fmtTime(event.ts)));
  const main = el('div', 'entry-main');
  const head = el('div', 'entry-head');
  head.appendChild(el('span', 'entry-type', desc.label));
  if (event.challenge_id != null) {
    head.appendChild(el('span', 'entry-challenge', challengeLabel(event.challenge_id)));
  }
  head.appendChild(el('span', 'entry-seq', `#${event.seq}`));
  main.appendChild(head);
  main.appendChild(el('div', 'entry-body', desc.body || ''));
  entry.appendChild(main);
  return entry;
}

function renderTimeline() {
  const box = $('timeline');
  const stick = $('follow').checked;
  const previousTop = box.scrollTop;
  box.textContent = '';
  setText('timeline-scope', state.scope == null ? '全部题目' : challengeLabel(state.scope));
  const visible = state.events.filter((event) => {
    if (state.scope == null) return true;
    if (event.challenge_id === state.scope) return true;
    if (event.challenge_id == null && (event.type === 'alert' || event.type.startsWith('system.'))) return true;
    return false;
  });
  if (visible.length === 0) {
    box.appendChild(el('div', 'empty', '暂无事件'));
    return;
  }
  for (const event of visible) {
    const node = buildEntry(event);
    if (node) box.appendChild(node);
  }
  if (stick) box.scrollTop = box.scrollHeight;
  else box.scrollTop = previousTop;
}

function appendEvent(event) {
  if (SKIP_TYPES.has(event.type) || event.type.endsWith('.delta')) return;
  // resync 快照与实时广播/ping 可能存在边界重叠，按 seq 去重
  if (state.events.length > 0 && event.seq <= state.events[state.events.length - 1].seq) {
    if (state.events.some((item) => item.seq === event.seq)) return;
  }
  state.events.push(event);
  if (state.events.length > MAX_EVENTS) {
    state.events.splice(0, state.events.length - MAX_EVENTS);
  }
  renderTimeline();
}

/* ------------------------------------------------------------------ websocket */
function setConn(ok, text) {
  $('conn-dot').className = `dot ${ok ? 'ok' : 'err'}`;
  setText('conn-text', text || (ok ? '已连接' : '已断开'));
}

function connectWS() {
  if (state.ws && (state.ws.readyState === WebSocket.OPEN || state.ws.readyState === WebSocket.CONNECTING)) {
    return;
  }
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const params = new URLSearchParams();
  if (state.helloReceived && !state.forceReset) {
    params.set('since_seq', String(state.lastSeq));
  }
  if (state.forceReset) params.set('reset', '1');
  const url = `${proto}//${location.host}/ws?${params.toString()}`;
  setConn(false, '连接中');
  const ws = new WebSocket(url);
  state.ws = ws;

  ws.addEventListener('open', () => {
    state.reconnectDelay = 1000;
    state.forceReset = false;
  });
  ws.addEventListener('message', (event) => {
    let payload;
    try {
      payload = JSON.parse(event.data);
    } catch (err) {
      console.error('bad ws message', err);
      return;
    }
    handleEnvelope(payload);
  });
  ws.addEventListener('close', () => {
    state.ws = null;
    setConn(false, '已断开');
    const delay = state.reconnectDelay;
    state.reconnectDelay = Math.min(10000, Math.round(state.reconnectDelay * 1.7));
    setTimeout(connectWS, delay);
  });
  ws.addEventListener('error', () => {
    try {
      ws.close();
    } catch (err) {
      /* ignore */
    }
  });
}

function forceResync() {
  state.forceReset = true;
  state.events = [];
  renderTimeline();
  state.reconnectDelay = 400;
  if (state.ws) {
    try {
      state.ws.close();
    } catch (err) {
      /* ignore */
    }
  } else {
    connectWS();
  }
}

function handleEnvelope(message) {
  if (typeof message.seq === 'number') {
    state.lastSeq = Math.max(state.lastSeq, message.seq);
  }
  if (message.type === 'hello') {
    onHello(message);
    return;
  }
  if (message.type === 'heartbeat') {
    applyOverview(message.payload && message.payload.overview);
    return;
  }
  if (message.type === 'pong') return;
  if (message.type === 'event.dropped') {
    showToast('事件队列溢出，正在重新同步…', true);
    forceResync();
    return;
  }
  if (message.type === 'discovery.tick') {
    if (state.overview && message.payload && message.payload.status) {
      state.overview.discovery = message.payload.status;
      renderStats();
      renderBadges();
    }
    return;
  }

  const payload = message.payload || {};
  if (message.type === 'platform.state' && state.overview) {
    if (payload.session) state.overview.session = payload.session;
    if (payload.discovery) state.overview.discovery = payload.discovery;
    renderBadges();
    renderStats();
  }
  if (payload.challenge && payload.challenge.id != null) {
    upsertChallenge(payload.challenge);
  }
  if (message.type === 'alert') {
    showToast(
      `${payload.level === 'error' ? '告警：' : '提示：'}${payload.message || ''}`,
      payload.level === 'error'
    );
  }
  appendEvent(message);
}

function onHello(message) {
  const payload = message.payload || {};
  state.helloReceived = true;
  state.reconnectDelay = 1000;
  if (payload.overview) applyOverview(payload.overview);
  if (Array.isArray(payload.challenges)) applyChallenges(payload.challenges);
  if (payload.resync) {
    state.events = Array.isArray(payload.events) ? payload.events.slice() : [];
  }
  if (typeof message.seq === 'number') state.lastSeq = Math.max(state.lastSeq, message.seq);
  renderAll();
  setConn(true, '已连接');
  if (payload.resync) renderTimeline();
}

/* ------------------------------------------------------------------ actions */
function updateActions() {
  const challenge = state.challenges.get(state.selectedId);
  const features = (state.overview && state.overview.features) || {};
  const selected = Boolean(challenge);
  const input = $('message-input');
  $('btn-send').disabled = !selected || input.value.trim().length === 0;
  $('btn-pause').disabled = !selected || !features.agent_control || challenge.status !== 'SOLVING';
  $('btn-stop').disabled =
    !selected || !features.agent_control || !['PREPARING', 'READY', 'SOLVING', 'PAUSED'].includes(challenge && challenge.status);
  $('btn-resume').disabled = !selected || !features.agent_control;
  $('btn-fresh').disabled = !selected || !features.agent_control;
  $('btn-submit').disabled = !selected || !features.auto_submit;
  input.disabled = !selected;
}

async function sendMessage() {
  if (state.selectedId == null) return;
  const input = $('message-input');
  const content = input.value.trim();
  if (!content) return;
  try {
    const result = await postJSON(`/api/challenges/${state.selectedId}/message`, { content });
    input.value = '';
    updateActions();
    showToast(result.message || (result.delivered ? '消息已投递' : '消息已记录'), 'ok');
    await loadDetail(state.selectedId);
  } catch (err) {
    showToast(`发送失败：${err.message}`, true);
  }
}

async function runCommand(kind, body) {
  if (state.selectedId == null) return;
  try {
    const result = await postJSON(`/api/challenges/${state.selectedId}/${kind}`, body);
    showToast(result.message || '已执行', 'ok');
    await loadDetail(state.selectedId);
  } catch (err) {
    showToast(err.message, true);
  }
}

async function stopAll() {
  const button = $('btn-stop-all');
  if (!state.stopAllArmed) {
    state.stopAllArmed = true;
    button.classList.add('armed');
    button.textContent = '再次点击确认停止全部';
    if (stopAllTimer) clearTimeout(stopAllTimer);
    stopAllTimer = setTimeout(resetStopAll, 4000);
    return;
  }
  resetStopAll();
  try {
    const result = await postJSON('/api/actions/stop-all');
    showToast(result.message || '已发送停止全部', 'ok');
  } catch (err) {
    showToast(err.message, true);
  }
}

function resetStopAll() {
  state.stopAllArmed = false;
  if (stopAllTimer) clearTimeout(stopAllTimer);
  stopAllTimer = null;
  const button = $('btn-stop-all');
  button.classList.remove('armed');
  button.textContent = '全部停止';
}

function openSubmitModal() {
  if (state.selectedId == null) return;
  const challenge = state.challenges.get(state.selectedId);
  const dryRun = state.overview && state.overview.dry_run;
  $('submit-modal-title').textContent = `${challenge ? challenge.title : ''} · ${
    dryRun ? 'dry_run=true：只记录，不会真正提交' : '将通过提交队列发送到平台'
  }`;
  $('submit-flag-input').value = '';
  $('submit-modal').classList.remove('hidden');
  $('submit-flag-input').focus();
}

function closeSubmitModal() {
  $('submit-modal').classList.add('hidden');
}

async function confirmSubmit() {
  const flag = $('submit-flag-input').value.trim();
  if (!flag || state.selectedId == null) return;
  try {
    const result = await postJSON(`/api/challenges/${state.selectedId}/submit`, { flag });
    showToast(result.message || '已提交', result.ok === false ? true : 'ok');
    closeSubmitModal();
    await loadDetail(state.selectedId);
  } catch (err) {
    showToast(err.message, true);
  }
}

/* ------------------------------------------------------------------ init */
function bindUI() {
  document.querySelectorAll('.filter').forEach((button) => {
    button.addEventListener('click', () => {
      state.filter = button.dataset.filter;
      document.querySelectorAll('.filter').forEach((item) => item.classList.toggle('active', item === button));
      renderChallengeList();
    });
  });

  const input = $('message-input');
  input.addEventListener('input', updateActions);
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      sendMessage();
    }
  });
  $('btn-send').addEventListener('click', sendMessage);

  $('btn-pause').addEventListener('click', () => runCommand('pause'));
  $('btn-stop').addEventListener('click', () => runCommand('stop'));
  $('btn-resume').addEventListener('click', () => runCommand('restart', { mode: 'resume' }));
  $('btn-fresh').addEventListener('click', () => runCommand('restart', { mode: 'fresh' }));
  $('btn-stop-all').addEventListener('click', stopAll);
  $('btn-submit').addEventListener('click', openSubmitModal);

  $('submit-cancel').addEventListener('click', closeSubmitModal);
  $('submit-confirm').addEventListener('click', confirmSubmit);
  $('submit-flag-input').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      confirmSubmit();
    }
  });

  $('btn-scope-all').addEventListener('click', () => {
    state.scope = null;
    $('btn-scope-all').classList.add('hidden');
    renderTimeline();
  });
  $('btn-clear-events').addEventListener('click', () => {
    state.events = [];
    renderTimeline();
  });

  const timeline = $('timeline');
  timeline.addEventListener('scroll', () => {
    const nearBottom = timeline.scrollHeight - timeline.scrollTop - timeline.clientHeight < 48;
    $('follow').checked = nearBottom;
  });

  $('btn-pause').title = '暂停 Agent';
  $('btn-stop').title = '停止 Agent';
  $('btn-resume').title = '重开 Agent（保留会话）';
  $('btn-fresh').title = '重开 Agent（新会话）';
  $('btn-submit').title = '手动提交单个 flag（遵守 dry_run 与去重规则）';
}

function renderAll() {
  renderStats();
  renderBadges();
  renderChallengeList();
  renderDetail();
  renderTimeline();
  updateActions();
}

async function bootstrap() {
  bindUI();
  updateCountdown();
  setInterval(updateCountdown, 1000);
  setInterval(() => {
    if (state.ws && state.ws.readyState === WebSocket.OPEN) {
      state.ws.send(JSON.stringify({ type: 'ping', ts: Date.now() }));
    }
  }, 25000);

  try {
    const [overview, challenges] = await Promise.all([
      getJSON('/api/overview'),
      getJSON('/api/challenges'),
    ]);
    applyOverview(overview);
    applyChallenges(challenges.challenges || []);
    renderAll();
  } catch (err) {
    showToast(`初始加载失败：${err.message}`, true);
  }
  connectWS();
}

document.addEventListener('DOMContentLoaded', bootstrap);

let currentTab = 0;
const currentFilter = {};
const currentSearch = {};
const renderedPanels = {};
const panelStates = {};

function loadReportData() {
  const dataEl = document.getElementById('callgraph-data');
  if (!dataEl || dataEl.textContent.trim() === '') {
    return [];
  }

  try {
    return JSON.parse(dataEl.textContent);
  } catch (error) {
    console.error('Failed to parse callgraph report payload', error);
    return [];
  }
}

const reportData = loadReportData();

function setActiveSidebarItem(idx) {
  document.querySelectorAll('.entry-item').forEach(function (item) {
    item.classList.toggle('active', parseInt(item.dataset.idx, 10) === idx);
  });
}

function createStatPill(dotClass, text) {
  const pill = document.createElement('div');
  pill.className = 'stat-pill';

  const dot = document.createElement('span');
  dot.className = 'dot ' + dotClass;
  pill.appendChild(dot);
  pill.appendChild(document.createTextNode(text));
  return pill;
}

function escapeHtml(text) {
  return String(text)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function createPanelState(root) {
  const children = new Array(root.nodes.length);
  const expanded = new Uint8Array(root.nodes.length);

  for (let nodeIndex = 0; nodeIndex < root.nodes.length; nodeIndex += 1) {
    children[nodeIndex] = [];
  }

  root.nodes.forEach(function (node, nodeIndex) {
    const parentIndex = node[2];
    if (parentIndex >= 0) {
      children[parentIndex].push(nodeIndex);
    }
  });

  return {
    root: root,
    children: children,
    expanded: expanded,
    panel: null,
    tbody: null,
  };
}

function getPanelState(idx) {
  if (!panelStates[idx]) {
    panelStates[idx] = createPanelState(reportData[idx]);
  }
  return panelStates[idx];
}

function buildTreeRowHtml(state, nodeIndex) {
  const node = state.root.nodes[nodeIndex];
  const level = node[1];
  const edgeTaken = node[3] === 1;
  const hitCount = node[4];
  const coveredChildren = node[5];
  const uncoveredChildren = node[6];
  const hasChildren = state.children[nodeIndex].length > 0;

  let badgeClass = '';
  let badgeText = '';
  if (level === 0) {
    badgeClass = 'badge badge-root';
    badgeText = '&diams; entry';
  } else if (coveredChildren + uncoveredChildren === 0) {
    badgeClass = 'badge ' + (edgeTaken ? 'badge-covered' : 'badge-uncovered');
    badgeText = edgeTaken ? '&check; leaf' : '&times; leaf';
  } else {
    badgeClass = 'badge ' + (edgeTaken ? 'badge-covered' : 'badge-uncovered');
    badgeText = edgeTaken ? '&check; taken' : '&times; not taken';
  }

  const toggleClass = 'tree-toggle' + (hasChildren ? '' : ' no-children');
  const toggleAttrs = hasChildren
    ? ' data-toggle-index="' + nodeIndex + '" data-expanded="' + (state.expanded[nodeIndex] === 1 ? 'true' : 'false') + '"'
    : '';
  const toggleText = hasChildren
    ? (state.expanded[nodeIndex] === 1 ? '&#9660;' : '&#9654;')
    : '&#9675;';
  const hitsHtml = hitCount > 0 ? '<span class="edge-hits">(' + hitCount + ')</span>' : '';

  return (
    '<tr class="tree-node"' +
    ' data-node-index="' + nodeIndex + '"' +
    ' data-parent-index="' + (node[2] < 0 ? '' : node[2]) + '"' +
    ' data-edge-status="' + (level === 0 || edgeTaken ? 'covered' : 'uncovered') + '"' +
    ' data-name="' + escapeHtml(node[0]) + '">' +
      '<td>' +
        '<div class="node-cell" style="--level:' + level + '">' +
          '<span class="' + toggleClass + '"' + toggleAttrs + '>' + toggleText + '</span>' +
          '<span class="node-name' + (level === 0 ? ' is-root' : '') + '">' + escapeHtml(node[0]) + '</span>' +
          hitsHtml +
        '</div>' +
      '</td>' +
      '<td class="status-cell">' +
        '<span class="' + badgeClass + '">' + badgeText + '</span>' +
      '</td>' +
    '</tr>'
  );
}

function collectVisibleNodeIndexes(state, tabIdx) {
  const root = state.root;
  const filter = currentFilter[tabIdx] || 'all';
  const search = currentSearch[tabIdx] || '';
  const hasQuery = filter !== 'all' || search !== '';

  if (!hasQuery) {
    const visible = [];
    const stack = [0];

    while (stack.length > 0) {
      const nodeIndex = stack.pop();
      visible.push(nodeIndex);

      if (state.expanded[nodeIndex] !== 1) {
        continue;
      }

      const children = state.children[nodeIndex];
      for (let childIdx = children.length - 1; childIdx >= 0; childIdx -= 1) {
        stack.push(children[childIdx]);
      }
    }

    return visible;
  }

  const included = new Uint8Array(root.nodes.length);
  const visible = [];

  root.nodes.forEach(function (node, nodeIndex) {
    const edgeStatus = node[1] === 0 || node[3] === 1 ? 'covered' : 'uncovered';
    const statusOk = filter === 'all' || edgeStatus === filter;
    const nameOk = search === '' || node[0].toLowerCase().includes(search);

    if (!statusOk || !nameOk) {
      return;
    }

    let currentIndex = nodeIndex;
    while (currentIndex >= 0 && included[currentIndex] === 0) {
      included[currentIndex] = 1;
      currentIndex = root.nodes[currentIndex][2];
    }
  });

  if (included[0] === 0) {
    included[0] = 1;
  }

  const stack = [0];
  while (stack.length > 0) {
    const nodeIndex = stack.pop();
    if (included[nodeIndex] === 0) {
      continue;
    }

    visible.push(nodeIndex);

    const children = state.children[nodeIndex];
    for (let childIdx = children.length - 1; childIdx >= 0; childIdx -= 1) {
      const childIndex = children[childIdx];
      if (included[childIndex] === 1) {
        stack.push(childIndex);
      }
    }
  }

  return visible;
}

function renderTree(state, tabIdx) {
  if (!state.tbody) {
    return;
  }

  const rows = [];
  collectVisibleNodeIndexes(state, tabIdx).forEach(function (nodeIndex) {
    rows.push(buildTreeRowHtml(state, nodeIndex));
  });

  state.tbody.innerHTML = rows.join('');
}

function buildPanel(root, idx) {
  const state = getPanelState(idx);

  const panel = document.createElement('div');
  panel.id = 'panel-' + idx;
  panel.className = 'panel';
  panel.style.display = 'none';

  const header = document.createElement('div');
  header.className = 'panel-header';

  const title = document.createElement('div');
  title.className = 'panel-title';
  title.textContent = root.name;
  header.appendChild(title);

  const statsRow = document.createElement('div');
  statsRow.className = 'stats-row';
  statsRow.appendChild(createStatPill('dot-total', root.nodeCount + ' nodes'));
  statsRow.appendChild(createStatPill('dot-covered', root.covered + ' covered'));
  statsRow.appendChild(createStatPill('dot-uncovered', root.uncovered + ' uncovered'));
  header.appendChild(statsRow);

  panel.appendChild(header);

  const toolbar = document.createElement('div');
  toolbar.className = 'toolbar';

  const search = document.createElement('input');
  search.type = 'text';
  search.placeholder = 'Search functions...';
  search.value = currentSearch[idx] || '';
  search.addEventListener('input', function (event) {
    filterTree(event.target.value, idx);
  });
  toolbar.appendChild(search);

  const expandButton = document.createElement('button');
  expandButton.type = 'button';
  expandButton.className = 'toolbar-btn';
  expandButton.textContent = 'Expand All';
  expandButton.addEventListener('click', function () {
    expandAll(idx);
  });
  toolbar.appendChild(expandButton);

  const collapseButton = document.createElement('button');
  collapseButton.type = 'button';
  collapseButton.className = 'toolbar-btn';
  collapseButton.textContent = 'Collapse All';
  collapseButton.addEventListener('click', function () {
    collapseAll(idx);
  });
  toolbar.appendChild(collapseButton);

  const filterGroup = document.createElement('div');
  filterGroup.className = 'filter-group';
  ['all', 'covered', 'uncovered'].forEach(function (filter) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'filter-btn';
    if ((currentFilter[idx] || 'all') === filter) {
      button.classList.add('active-' + filter);
    }
    button.dataset.filter = filter;
    button.dataset.tab = String(idx);
    button.textContent = filter.charAt(0).toUpperCase() + filter.slice(1);
    button.addEventListener('click', function () {
      setFilter(filter, idx);
    });
    filterGroup.appendChild(button);
  });
  toolbar.appendChild(filterGroup);

  panel.appendChild(toolbar);

  const treeWrap = document.createElement('div');
  treeWrap.className = 'tree-wrap';

  const table = document.createElement('table');
  const thead = document.createElement('thead');
  const headRow = document.createElement('tr');

  const functionHeader = document.createElement('th');
  functionHeader.textContent = 'Function';
  headRow.appendChild(functionHeader);

  const statusHeader = document.createElement('th');
  statusHeader.style.width = '160px';
  statusHeader.textContent = 'Status';
  headRow.appendChild(statusHeader);

  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');
  tbody.id = 'tbody-' + idx;
  table.appendChild(tbody);

  treeWrap.appendChild(table);
  panel.appendChild(treeWrap);

  state.panel = panel;
  state.tbody = tbody;
  renderTree(state, idx);
  return panel;
}

function ensurePanelRendered(idx) {
  if (renderedPanels[idx]) {
    return renderedPanels[idx];
  }

  const root = reportData[idx];
  const main = document.getElementById('main');
  if (!root || !main) {
    return null;
  }

  const panel = buildPanel(root, idx);
  main.appendChild(panel);
  renderedPanels[idx] = panel;
  return panel;
}

function setActivePanel(idx) {
  const panel = ensurePanelRendered(idx);
  document.querySelectorAll('[id^="panel-"]').forEach(function (existingPanel) {
    existingPanel.style.display = 'none';
  });

  if (panel) {
    panel.style.display = 'flex';
  }
}

function applyVisibility(tabIdx) {
  ensurePanelRendered(tabIdx);
  const state = panelStates[tabIdx];
  if (!state) {
    return;
  }

  renderTree(state, tabIdx);
}

function selectRoot(idx) {
  setActiveSidebarItem(idx);
  setActivePanel(idx);
  currentTab = idx;
  applyVisibility(idx);
}

function toggleNode(toggleEl) {
  const nodeIndex = parseInt(toggleEl.dataset.toggleIndex, 10);
  if (Number.isNaN(nodeIndex)) {
    return;
  }

  const panel = toggleEl.closest('.panel');
  if (!panel) {
    return;
  }

  const idx = parseInt(panel.id.replace('panel-', ''), 10);
  if (Number.isNaN(idx)) {
    return;
  }

  const state = getPanelState(idx);
  state.expanded[nodeIndex] = state.expanded[nodeIndex] === 1 ? 0 : 1;
  renderTree(state, idx);
}

function expandAll(tabIdx) {
  ensurePanelRendered(tabIdx);
  const state = panelStates[tabIdx];
  if (!state) {
    return;
  }

  state.expanded.fill(1);
  renderTree(state, tabIdx);
}

function collapseAll(tabIdx) {
  ensurePanelRendered(tabIdx);
  const state = panelStates[tabIdx];
  if (!state) {
    return;
  }

  state.expanded.fill(0);
  renderTree(state, tabIdx);
}

function setFilter(filter, tabIdx) {
  currentFilter[tabIdx] = filter;
  document.querySelectorAll('[data-filter][data-tab="' + tabIdx + '"]').forEach(function (button) {
    button.className = 'filter-btn';
    if (button.dataset.filter === filter) {
      button.classList.add('active-' + filter);
    }
  });
  applyVisibility(tabIdx);
}

function filterTree(query, tabIdx) {
  currentSearch[tabIdx] = query.toLowerCase();
  applyVisibility(tabIdx);
}

function filterSidebar(query) {
  const needle = query.toLowerCase();
  document.querySelectorAll('.entry-card').forEach(function (card) {
    const name = card.querySelector('.entry-name');
    const match = name && name.textContent.toLowerCase().includes(needle);
    card.style.display = match ? '' : 'none';
  });
}

document.addEventListener('click', function (event) {
  if (event.target.classList.contains('tree-toggle') && event.target.dataset.toggleIndex) {
    toggleNode(event.target);
  }
});

document.addEventListener('DOMContentLoaded', function () {
  if (reportData.length > 0) {
    selectRoot(0);
  }
});

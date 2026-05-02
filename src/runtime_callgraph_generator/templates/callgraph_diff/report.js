let currentTab = 0;
const currentFilter = {};
const currentSearch = {};
const renderedPanels = {};

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

function setToggleState(toggleEl, expanded) {
  toggleEl.dataset.expanded = expanded ? 'true' : 'false';
  toggleEl.innerHTML = expanded ? '&#9660;' : '&#9654;';
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

function createTreeRow(node, nodeIndex) {
  const level = node[1];
  const parentIndex = node[2];
  const edgeTaken = node[3] === 1;
  const hitCount = node[4];
  const coveredChildren = node[5];
  const uncoveredChildren = node[6];
  const hasChildren = coveredChildren + uncoveredChildren > 0;

  const row = document.createElement('tr');
  row.className = 'tree-node' + (level !== 0 ? ' tree-hidden' : '');
  row.dataset.nodeIndex = String(nodeIndex);
  row.dataset.parentIndex = parentIndex < 0 ? '' : String(parentIndex);
  row.dataset.edgeStatus = level === 0 || edgeTaken ? 'covered' : 'uncovered';
  row.dataset.name = node[0];

  const functionCell = document.createElement('td');
  const nodeCell = document.createElement('div');
  nodeCell.className = 'node-cell';

  for (let indentLevel = 0; indentLevel < level; indentLevel += 1) {
    const indent = document.createElement('span');
    indent.className = 'ident-block';
    nodeCell.appendChild(indent);
  }

  const toggle = document.createElement('span');
  toggle.className = 'tree-toggle' + (hasChildren ? '' : ' no-children');
  if (hasChildren) {
    toggle.dataset.toggleIndex = String(nodeIndex);
    setToggleState(toggle, true);
  } else {
    toggle.innerHTML = '&#9675;';
  }
  nodeCell.appendChild(toggle);

  const name = document.createElement('span');
  name.className = 'node-name' + (level === 0 ? ' is-root' : '');
  name.textContent = node[0];
  nodeCell.appendChild(name);

  if (hitCount > 0) {
    const hits = document.createElement('span');
    hits.className = 'edge-hits';
    hits.textContent = '(' + hitCount + ')';
    nodeCell.appendChild(hits);
  }

  functionCell.appendChild(nodeCell);
  row.appendChild(functionCell);

  const statusCell = document.createElement('td');
  statusCell.className = 'status-cell';

  const badge = document.createElement('span');
  if (level === 0) {
    badge.className = 'badge badge-root';
    badge.innerHTML = '&diams; entry';
  } else if (coveredChildren + uncoveredChildren === 0) {
    badge.className = 'badge ' + (edgeTaken ? 'badge-covered' : 'badge-uncovered');
    badge.innerHTML = edgeTaken ? '&check; leaf' : '&times; leaf';
  } else {
    badge.className = 'badge ' + (edgeTaken ? 'badge-covered' : 'badge-uncovered');
    badge.innerHTML = edgeTaken ? '&check; taken' : '&times; not taken';
  }

  statusCell.appendChild(badge);
  row.appendChild(statusCell);

  return row;
}

function buildPanel(root, idx) {
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

  const rows = document.createDocumentFragment();
  root.nodes.forEach(function (node, nodeIndex) {
    rows.appendChild(createTreeRow(node, nodeIndex));
  });
  tbody.appendChild(rows);
  table.appendChild(tbody);

  treeWrap.appendChild(table);
  panel.appendChild(treeWrap);

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

function hideDescendants(tbody, nodeIndex) {
  tbody.querySelectorAll('[data-parent-index="' + nodeIndex + '"]').forEach(function (row) {
    row.classList.add('tree-hidden');
    hideDescendants(tbody, row.dataset.nodeIndex);
  });
}

function showDescendants(tbody, nodeIndex) {
  tbody.querySelectorAll('[data-parent-index="' + nodeIndex + '"]').forEach(function (row) {
    row.classList.remove('tree-hidden');
    const toggle = row.querySelector('[data-toggle-index]');
    if (toggle && toggle.dataset.expanded === 'true') {
      showDescendants(tbody, row.dataset.nodeIndex);
    } else {
      hideDescendants(tbody, row.dataset.nodeIndex);
    }
  });
}

function restoreCollapseState(tbody, nodeIndex) {
  const row = tbody.querySelector('[data-node-index="' + nodeIndex + '"]');
  if (!row) {
    return;
  }

  row.classList.remove('tree-hidden');
  const toggle = row.querySelector('[data-toggle-index]');
  if (toggle && toggle.dataset.expanded === 'true') {
    showDescendants(tbody, nodeIndex);
  } else {
    hideDescendants(tbody, nodeIndex);
  }
}

function applyVisibility(tabIdx) {
  ensurePanelRendered(tabIdx);
  const tbody = document.getElementById('tbody-' + tabIdx);
  if (!tbody) {
    return;
  }

  const filter = currentFilter[tabIdx] || 'all';
  const search = currentSearch[tabIdx] || '';
  const isFiltering = filter !== 'all' || search !== '';

  tbody.querySelectorAll('.tree-node').forEach(function (row) {
    const statusOk = filter === 'all' || row.dataset.edgeStatus === filter;
    const nameOk = search === '' || (row.dataset.name || '').toLowerCase().includes(search);
    row.classList.toggle('filter-hidden', !(statusOk && nameOk));
  });

  if (isFiltering) {
    tbody.querySelectorAll('.tree-node:not(.filter-hidden)').forEach(function (row) {
      row.classList.remove('tree-hidden');

      let parentIndex = row.dataset.parentIndex;
      while (parentIndex !== '') {
        const parent = tbody.querySelector('[data-node-index="' + parentIndex + '"]');
        if (!parent) {
          break;
        }
        parent.classList.remove('tree-hidden');
        parentIndex = parent.dataset.parentIndex || '';
      }
    });
    return;
  }

  tbody.querySelectorAll('.tree-node').forEach(function (row) {
    row.classList.remove('filter-hidden');
  });

  tbody.querySelectorAll('.tree-node[data-parent-index=""]').forEach(function (root) {
    restoreCollapseState(tbody, root.dataset.nodeIndex);
  });
}

function selectRoot(idx) {
  setActiveSidebarItem(idx);
  setActivePanel(idx);
  currentTab = idx;
  applyVisibility(idx);
}

function toggleNode(toggleEl) {
  const nodeIndex = toggleEl.dataset.toggleIndex;
  if (!nodeIndex) {
    return;
  }

  const tbody = toggleEl.closest('tbody');
  if (!tbody) {
    return;
  }

  const expanded = toggleEl.dataset.expanded === 'true';
  if (expanded) {
    hideDescendants(tbody, nodeIndex);
    setToggleState(toggleEl, false);
  } else {
    showDescendants(tbody, nodeIndex);
    setToggleState(toggleEl, true);
  }
}

function expandAll(tabIdx) {
  ensurePanelRendered(tabIdx);
  const tbody = document.getElementById('tbody-' + tabIdx);
  if (!tbody) {
    return;
  }

  tbody.querySelectorAll('.tree-node').forEach(function (row) {
    row.classList.remove('tree-hidden');
    row.classList.remove('filter-hidden');
  });

  tbody.querySelectorAll('[data-toggle-index]').forEach(function (toggleEl) {
    setToggleState(toggleEl, true);
  });
}

function collapseAll(tabIdx) {
  ensurePanelRendered(tabIdx);
  const tbody = document.getElementById('tbody-' + tabIdx);
  if (!tbody) {
    return;
  }

  tbody.querySelectorAll('.tree-node').forEach(function (row) {
    row.classList.remove('filter-hidden');
    if (row.dataset.parentIndex !== '') {
      row.classList.add('tree-hidden');
    }
  });

  tbody.querySelectorAll('[data-toggle-index]').forEach(function (toggleEl) {
    setToggleState(toggleEl, false);
  });
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

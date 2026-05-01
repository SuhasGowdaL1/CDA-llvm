let currentTab = 0;
const currentFilter = {};
const currentSearch = {};

function setActiveSidebarItem(idx) {
  document.querySelectorAll('.entry-item').forEach(function (item) {
    item.classList.toggle('active', parseInt(item.dataset.idx, 10) === idx);
  });
}

function setActivePanel(idx) {
  document.querySelectorAll('[id^="panel-"]').forEach(function (panel) {
    panel.style.display = 'none';
  });

  const panel = document.getElementById('panel-' + idx);
  if (panel) {
    panel.style.display = 'flex';
  }
}

function setToggleState(toggleEl, expanded) {
  toggleEl.dataset.expanded = expanded ? 'true' : 'false';
  toggleEl.innerHTML = expanded ? '&#9660;' : '&#9654;';
}

function hideDescendants(tbody, uid) {
  tbody.querySelectorAll('[data-parent-uid="' + uid + '"]').forEach(function (row) {
    row.classList.add('tree-hidden');
    hideDescendants(tbody, row.dataset.uid);
  });
}

function showDescendants(tbody, uid) {
  tbody.querySelectorAll('[data-parent-uid="' + uid + '"]').forEach(function (row) {
    row.classList.remove('tree-hidden');
    const toggle = row.querySelector('[data-toggle-uid]');
    if (toggle && toggle.dataset.expanded === 'true') {
      showDescendants(tbody, row.dataset.uid);
    } else {
      hideDescendants(tbody, row.dataset.uid);
    }
  });
}

function restoreCollapseState(tbody, uid) {
  const row = tbody.querySelector('[data-uid="' + uid + '"]');
  if (!row) {
    return;
  }

  row.classList.remove('tree-hidden');
  const toggle = row.querySelector('[data-toggle-uid]');
  if (toggle && toggle.dataset.expanded === 'true') {
    showDescendants(tbody, uid);
  } else {
    hideDescendants(tbody, uid);
  }
}

function applyVisibility(tabIdx) {
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

      let parentUid = row.dataset.parentUid;
      while (parentUid) {
        const parent = tbody.querySelector('[data-uid="' + parentUid + '"]');
        if (!parent) {
          break;
        }
        parent.classList.remove('tree-hidden');
        parentUid = parent.dataset.parentUid || '';
      }
    });
    return;
  }

  tbody.querySelectorAll('.tree-node').forEach(function (row) {
    row.classList.remove('filter-hidden');
  });

  tbody.querySelectorAll('.tree-node[data-parent-uid=""]').forEach(function (root) {
    restoreCollapseState(tbody, root.dataset.uid);
  });
}

function selectRoot(idx) {
  setActiveSidebarItem(idx);
  setActivePanel(idx);
  currentTab = idx;
  applyVisibility(idx);
}

function toggleNode(toggleEl) {
  const uid = toggleEl.dataset.toggleUid;
  if (!uid) {
    return;
  }

  const tbody = toggleEl.closest('tbody');
  if (!tbody) {
    return;
  }

  const expanded = toggleEl.dataset.expanded === 'true';
  if (expanded) {
    hideDescendants(tbody, uid);
    setToggleState(toggleEl, false);
  } else {
    showDescendants(tbody, uid);
    setToggleState(toggleEl, true);
  }
}

function expandAll(tabIdx) {
  const tbody = document.getElementById('tbody-' + tabIdx);
  if (!tbody) {
    return;
  }

  tbody.querySelectorAll('.tree-node').forEach(function (row) {
    row.classList.remove('tree-hidden');
    row.classList.remove('filter-hidden');
  });

  tbody.querySelectorAll('[data-toggle-uid]').forEach(function (toggleEl) {
    setToggleState(toggleEl, true);
  });
}

function collapseAll(tabIdx) {
  const tbody = document.getElementById('tbody-' + tabIdx);
  if (!tbody) {
    return;
  }

  tbody.querySelectorAll('.tree-node').forEach(function (row) {
    row.classList.remove('filter-hidden');
    if (row.dataset.parentUid !== '') {
      row.classList.add('tree-hidden');
    }
  });

  tbody.querySelectorAll('[data-toggle-uid]').forEach(function (toggleEl) {
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
  if (event.target.classList.contains('tree-toggle') && event.target.dataset.toggleUid) {
    toggleNode(event.target);
  }
});

document.addEventListener('DOMContentLoaded', function () {
  if (document.getElementById('panel-0')) {
    selectRoot(0);
  }
});

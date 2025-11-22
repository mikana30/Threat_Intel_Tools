document.addEventListener('DOMContentLoaded', () => {
    const iconGrid = document.getElementById('icon-grid');
    const dataView = document.getElementById('data-view');
    const searchBox = document.getElementById('search-box');
    const backButton = document.getElementById('back-button');
    const dataTitle = document.getElementById('data-title');
    const tableHead = document.getElementById('table-head');
    const tableBody = document.getElementById('table-body');

    let vulnerabilities = [];
    let groupedData = {};
    let activeCategoryData = [];
    let currentViewData = [];
    let sortColumn = -1;
    let sortAsc = true;

    function initialize(data) {
        vulnerabilities = Array.isArray(data) ? data : [];
        groupedData = groupBySourceFile(vulnerabilities);
        renderIconGrid();
        setupEventListeners();
    }

    function groupBySourceFile(data) {
        return data.reduce((acc, item) => {
            const key = item.source_file || 'uncategorized';
            if (!acc[key]) {
                acc[key] = [];
            }
            acc[key].push(item);
            return acc;
        }, {});
    }

    function renderIconGrid() {
        iconGrid.innerHTML = '';
        iconGrid.classList.remove('is-hidden');
        iconGrid.setAttribute('aria-hidden', 'false');
        iconGrid.setAttribute('role', 'list');

        const sourceFiles = Object.keys(groupedData).sort((a, b) => a.localeCompare(b));

        sourceFiles.forEach((sourceFile) => {
            const readableName = sourceFile.replace(/_/g, ' ').replace(/\.(csv|txt)$/i, '');

            const card = document.createElement('div');
            card.className = 'icon-card';
            card.dataset.sourceFile = sourceFile;
            card.setAttribute('tabindex', '0');
            card.setAttribute('role', 'button');
            card.setAttribute('aria-label', `Open ${readableName}`);

            const icon = document.createElement('div');
            icon.className = 'icon';
            icon.textContent = '📄';

            const title = document.createElement('div');
            title.className = 'title';
            title.textContent = readableName;

            const count = document.createElement('div');
            count.className = 'record-count';
            count.textContent = `${groupedData[sourceFile].length} records`;

            card.appendChild(icon);
            card.appendChild(title);
            card.appendChild(count);
            iconGrid.appendChild(card);
        });
    }

    function renderTable(data) {
        tableHead.innerHTML = '';
        tableBody.innerHTML = '';

        currentViewData = Array.isArray(data) ? data : [];

        if (!currentViewData.length) {
            const emptyRow = document.createElement('tr');
            const emptyCell = document.createElement('td');
            emptyCell.colSpan = 1;
            emptyCell.className = 'empty-cell';
            emptyCell.textContent = 'No records are available for this category.';
            emptyRow.appendChild(emptyCell);
            tableBody.appendChild(emptyRow);
            return;
        }

        const headers = Object.keys(currentViewData[0]).filter((header) => header !== 'source_file');

        if (!headers.length) {
            const emptyRow = document.createElement('tr');
            const emptyCell = document.createElement('td');
            emptyCell.colSpan = 1;
            emptyCell.className = 'empty-cell';
            emptyCell.textContent = 'No tabular data available.';
            emptyRow.appendChild(emptyCell);
            tableBody.appendChild(emptyRow);
            return;
        }

        const headerRow = document.createElement('tr');

        headers.forEach((header, index) => {
            const th = document.createElement('th');
            th.textContent = header;
            th.dataset.columnIndex = index;
            headerRow.appendChild(th);
        });

        tableHead.appendChild(headerRow);

        currentViewData.forEach((item) => {
            const row = document.createElement('tr');

            headers.forEach((header) => {
                const td = document.createElement('td');
                const value = item[header];
                td.textContent = value || value === 0 ? value : 'N/A';
                row.appendChild(td);
            });

            tableBody.appendChild(row);
        });
    }

    function openCategory(sourceFile) {
        activeCategoryData = groupedData[sourceFile] || [];
        sortColumn = -1;
        sortAsc = true;

        const readableName = sourceFile.replace(/_/g, ' ').replace(/\.(csv|txt)$/i, '');
        dataTitle.textContent = readableName;

        renderTable(activeCategoryData);

        iconGrid.classList.add('is-hidden');
        iconGrid.setAttribute('aria-hidden', 'true');

        dataView.classList.add('active');
        dataView.setAttribute('aria-hidden', 'false');

        searchBox.value = '';
        searchBox.focus({ preventScroll: true });
    }

    function filterAndRenderTable() {
        const searchTerm = searchBox.value.trim().toLowerCase();

        if (searchTerm.length > 1) {
            const filteredData = activeCategoryData.filter((item) =>
                Object.values(item).some((value) =>
                    String(value ?? '').toLowerCase().includes(searchTerm)
                )
            );
            renderTable(filteredData);
        } else {
            renderTable(activeCategoryData);
        }
    }

    function sortTable(columnIndex) {
        if (!currentViewData.length) {
            return;
        }

        if (sortColumn === columnIndex) {
            sortAsc = !sortAsc;
        } else {
            sortColumn = columnIndex;
            sortAsc = true;
        }

        const headerKeys = Object.keys(currentViewData[0]).filter((header) => header !== 'source_file');
        const sortKey = headerKeys[columnIndex];

        if (!sortKey) {
            return;
        }

        const rowsArray = Array.from(tableBody.rows);

        rowsArray.sort((a, b) => {
            const aText = a.cells[columnIndex].textContent.trim();
            const bText = b.cells[columnIndex].textContent.trim();

            if (aText < bText) return sortAsc ? -1 : 1;
            if (aText > bText) return sortAsc ? 1 : -1;
            return 0;
        });

        tableBody.innerHTML = '';
        rowsArray.forEach((row) => tableBody.appendChild(row));
    }

    function resetView() {
        dataView.classList.remove('active');
        dataView.setAttribute('aria-hidden', 'true');

        iconGrid.classList.remove('is-hidden');
        iconGrid.setAttribute('aria-hidden', 'false');

        dataTitle.textContent = '';
        tableHead.innerHTML = '';
        tableBody.innerHTML = '';

        searchBox.value = '';
        activeCategoryData = [];
        currentViewData = [];
        sortColumn = -1;
        sortAsc = true;

        const firstCard = iconGrid.querySelector('.icon-card');
        if (firstCard) {
            firstCard.focus({ preventScroll: true });
        }
    }

    function setupEventListeners() {
        iconGrid.addEventListener('click', (event) => {
            const card = event.target.closest('.icon-card');
            if (card) {
                openCategory(card.dataset.sourceFile);
            }
        });

        iconGrid.addEventListener('keydown', (event) => {
            const card = event.target.closest('.icon-card');
            if (card && (event.key === 'Enter' || event.key === ' ')) {
                event.preventDefault();
                openCategory(card.dataset.sourceFile);
            }
        });

        backButton.addEventListener('click', resetView);

        searchBox.addEventListener('input', filterAndRenderTable);

        tableHead.addEventListener('click', (event) => {
            const th = event.target.closest('th');
            if (th) {
                sortTable(parseInt(th.dataset.columnIndex, 10));
            }
        });
    }

    if (typeof appendixData !== 'undefined') {
        initialize(appendixData);
    } else {
        console.error('Appendix data not found.');
        const app = document.getElementById('app');
        if (app) {
            app.innerHTML = '<p class="error-message">Error: Could not load vulnerability data.</p>';
        }
    }
});

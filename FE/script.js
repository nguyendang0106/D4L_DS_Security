/**
 * ===========================================
 * Network Intrusion Detection System (NIDS)
 * Real-time Monitoring Dashboard
 * ===========================================
 * 
 * This script handles real-time network traffic monitoring
 * using FastAPI backend with ML pipeline (OCSVM + Random Forest)
 * 
 * Features:
 * - Real-time streaming from 8 CSV files (circular rotation)
 * - Batch processing (3000 rows per batch)
 * - Live charts (Pie + Line) with Chart.js
 * - System logs with real-time updates
 * - Throughput calculation
 */

// ===========================================
// Configuration
// ===========================================
const API_BASE = 'http://127.0.0.1:8000';
const BATCH_SIZE = 3000;
const FETCH_INTERVAL = 1000; // 1 second
const MAX_BATCH_HISTORY = 20;

// ===========================================
// Global State
// ===========================================
let isMonitoring = false;
let pieChart = null;
let lineChart = null;
let dbPieChart = null;
let dbLineChart = null;
let totalPredictions = {};
let batchHistory = [];
let startTime = null;
let totalRowsProcessed = 0;

// Storage page state
let storageAutoRefreshInterval = null;
const STORAGE_REFRESH_INTERVAL = 5000; // 5 seconds

// Database analytics state
let dbAnalyticsInterval = null;
const DB_ANALYTICS_REFRESH_INTERVAL = 10000; // 10 seconds

// Chart colors
const CHART_COLORS = [
    '#667eea', '#764ba2', '#f093fb', '#f5576c',
    '#4facfe', '#00f2fe', '#43e97b', '#38f9d7',
    '#fa709a', '#fee140', '#30cfd0', '#330867',
    '#a8edea', '#fed6e3', '#ff9a9e', '#fad0c4'
];

// ===========================================
// Chart Initialization
// ===========================================

/**
 * Initialize Chart.js charts (Pie and Line)
 */
function initCharts() {
    // Pie Chart - Attack Type Distribution
    const pieCtx = document.getElementById('pieChart').getContext('2d');
    pieChart = new Chart(pieCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: CHART_COLORS,
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        padding: 15,
                        font: {
                            size: 12
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(1);
                            return `${label}: ${value.toLocaleString()} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });

    // Line Chart - Real-time Trends
    const lineCtx = document.getElementById('lineChart').getContext('2d');
    lineChart = new Chart(lineCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: []
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Number of Predictions'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Batch ID'
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        padding: 10,
                        font: {
                            size: 11
                        }
                    }
                },
                tooltip: {
                    mode: 'index',
                    intersect: false
                }
            },
            interaction: {
                mode: 'nearest',
                axis: 'x',
                intersect: false
            }
        }
    });

    // Database Pie Chart - Attack Distribution from Storage
    const dbPieCtx = document.getElementById('dbPieChart').getContext('2d');
    dbPieChart = new Chart(dbPieCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: CHART_COLORS,
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        padding: 15,
                        font: {
                            size: 12
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(1);
                            return `${label}: ${value.toLocaleString()} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });

    // Database Line Chart - Trend over time (by category)
    const dbLineCtx = document.getElementById('dbLineChart').getContext('2d');
    dbLineChart = new Chart(dbLineCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: []
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Number of Records'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Categories'
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        padding: 10,
                        font: {
                            size: 11
                        }
                    }
                },
                tooltip: {
                    mode: 'index',
                    intersect: false
                }
            }
        }
    });

    // Start fetching database analytics
    fetchDatabaseAnalytics();
    dbAnalyticsInterval = setInterval(fetchDatabaseAnalytics, DB_ANALYTICS_REFRESH_INTERVAL);
}

// ===========================================
// Monitoring Control Functions
// ===========================================

/**
 * Start real-time monitoring
 */
async function startMonitoring() {
    try {
        // Reset state
        isMonitoring = true;
        startTime = Date.now();
        totalRowsProcessed = 0;
        totalPredictions = {};
        batchHistory = [];

        // Update UI
        document.getElementById('startBtn').disabled = true;
        document.getElementById('stopBtn').disabled = false;
        document.getElementById('liveIndicator').classList.add('active');
        
        addLog('Starting streaming mode...', 'info');

        // Call API to start streaming
        const response = await fetch(`${API_BASE}/streaming/start?batch_size=${BATCH_SIZE}`, {
            method: 'POST'
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        
        addLog(`Streaming started successfully!`, 'success');
        addLog(`Total files in rotation: ${data.total_files}`, 'data');
        addLog(`Files: ${data.files.map(f => f.split('/').pop()).join(', ')}`, 'data');
        addLog(`Batch size: ${data.batch_size} rows`, 'data');

        // Start fetching batches
        fetchBatches();
        
    } catch (error) {
        addLog(`Failed to start streaming: ${error.message}`, 'error');
        await stopMonitoring();
    }
}

/**
 * Stop monitoring
 */
async function stopMonitoring() {
    isMonitoring = false;
    
    // Update UI
    document.getElementById('startBtn').disabled = false;
    document.getElementById('stopBtn').disabled = true;
    document.getElementById('liveIndicator').classList.remove('active');
    
    addLog('Stopping streaming...', 'info');

    try {
        const response = await fetch(`${API_BASE}/streaming/stop`, {
            method: 'POST'
        });

        if (response.ok) {
            const data = await response.json();
            
            addLog(`Streaming stopped successfully!`, 'success');
            addLog(`Total batches served: ${data.statistics.total_batches_served}`, 'data');
            addLog(`Total rows processed: ${data.statistics.total_rows_read.toLocaleString()}`, 'data');
            addLog(`Files processed: ${data.statistics.total_files_read}`, 'data');
        }
    } catch (error) {
        addLog(`Error while stopping: ${error.message}`, 'error');
    }
}

// ===========================================
// Data Fetching Functions
// ===========================================

/**
 * Continuously fetch batches from the server
 */
async function fetchBatches() {
    while (isMonitoring) {
        // Show loading indicator
        document.getElementById('loading').classList.add('active');
        
        try {
            const batchStart = Date.now();
            
            // Fetch next batch
            const response = await fetch(`${API_BASE}/streaming/next_batch`);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            const batchTime = (Date.now() - batchStart) / 1000;

            if (data.status === 'success') {
                updateDashboard(data, batchTime);
            } else {
                addLog(`No valid data in batch ${data.batch_id}`, 'warning');
            }
            
        } catch (error) {
            addLog(`Error fetching batch: ${error.message}`, 'error');
            
            // If multiple errors, stop monitoring
            if (!isMonitoring) break;
        } finally {
            // Hide loading indicator
            document.getElementById('loading').classList.remove('active');
        }
        
        // Wait before next fetch
        await sleep(FETCH_INTERVAL);
    }
}

// ===========================================
// Dashboard Update Functions
// ===========================================

/**
 * Update dashboard with new batch data
 * @param {Object} data - Batch data from API
 * @param {Number} batchTime - Time taken to process batch (seconds)
 */
function updateDashboard(data, batchTime) {
    // Update statistics cards
    updateStats(data);
    
    // Accumulate predictions
    accumulatePredictions(data.summary.prediction_distribution);
    
    // Store batch history
    storeBatchHistory(data);
    
    // Update charts
    updatePieChart();
    updateLineChart();
    
    // Add log entry
    logBatchProcessing(data, batchTime);
}

/**
 * Update statistics cards
 * @param {Object} data - Batch data
 */
function updateStats(data) {
    // Total Rows
    document.getElementById('totalRows').textContent = data.total_rows_read.toLocaleString();
    
    // Throughput
    const elapsedTime = (Date.now() - startTime) / 1000;
    const throughput = Math.round(data.total_rows_read / elapsedTime);
    document.getElementById('throughput').textContent = throughput.toLocaleString();
}

/**
 * Accumulate prediction counts
 * @param {Object} distribution - Prediction distribution from current batch
 */
function accumulatePredictions(distribution) {
    for (const [label, count] of Object.entries(distribution)) {
        totalPredictions[label] = (totalPredictions[label] || 0) + count;
    }
}

/**
 * Store batch in history (for line chart)
 * @param {Object} data - Batch data
 */
function storeBatchHistory(data) {
    batchHistory.push({
        batchId: data.batch_id,
        distribution: { ...data.summary.prediction_distribution }
    });

    // Keep only last N batches
    if (batchHistory.length > MAX_BATCH_HISTORY) {
        batchHistory.shift();
    }
}

/**
 * Update pie chart with accumulated predictions
 */
function updatePieChart() {
    const labels = Object.keys(totalPredictions);
    const data = Object.values(totalPredictions);

    pieChart.data.labels = labels;
    pieChart.data.datasets[0].data = data;
    pieChart.update();
}

/**
 * Update line chart with batch history
 */
function updateLineChart() {
    const labels = batchHistory.map(b => `#${b.batchId}`);
    
    // Get all unique prediction types across all batches
    const allTypes = new Set();
    batchHistory.forEach(b => {
        Object.keys(b.distribution).forEach(type => allTypes.add(type));
    });

    // Create dataset for each prediction type
    const datasets = Array.from(allTypes).map((type, index) => ({
        label: type,
        data: batchHistory.map(b => b.distribution[type] || 0),
        borderColor: CHART_COLORS[index % CHART_COLORS.length],
        backgroundColor: CHART_COLORS[index % CHART_COLORS.length] + '20', // 20 = alpha
        fill: false,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 6
    }));

    lineChart.data.labels = labels;
    lineChart.data.datasets = datasets;
    lineChart.update();
}

// ===========================================
// Logging Functions
// ===========================================

/**
 * Log batch processing info
 * @param {Object} data - Batch data
 * @param {Number} batchTime - Processing time in seconds
 */
function logBatchProcessing(data, batchTime) {
    const distribution = data.summary.prediction_distribution;
    const entries = Object.entries(distribution);
    
    // Sort by count descending
    entries.sort((a, b) => b[1] - a[1]);
    
    // Get top prediction
    const [topLabel, topCount] = entries[0];
    
    // Calculate throughput for this batch
    const batchThroughput = Math.round(data.batch_size / batchTime);
    
    addLog(
        `Batch #${data.batch_id}: ` +
        `${data.batch_size} predictions in ${batchTime.toFixed(2)}s ` +
        `(${batchThroughput} rows/s) | ` +
        `Top: ${topLabel} (${topCount})`
    );
}

/**
 * Add log entry to log container
 * @param {String} message - Log message
 * @param {String} type - Log type: 'info', 'success', 'warning', 'error', 'data'
 */
function addLog(message, type = 'info') {
    const logContainer = document.getElementById('logContainer');
    const timestamp = new Date().toLocaleTimeString();
    
    const logEntry = document.createElement('div');
    logEntry.className = `log-entry log-${type}`;
    
    // Create log indicator
    const indicator = document.createElement('span');
    indicator.className = 'log-indicator';
    
    // Create log content
    const content = document.createElement('span');
    content.className = 'log-content';
    content.innerHTML = `<span class="log-time">[${timestamp}]</span> ${message}`;
    
    logEntry.appendChild(indicator);
    logEntry.appendChild(content);
    logContainer.appendChild(logEntry);
    
    // Auto-scroll to bottom
    logContainer.scrollTop = logContainer.scrollHeight;
    
    // Animate entry
    setTimeout(() => logEntry.classList.add('log-visible'), 10);
}

// ===========================================
// Utility Functions
// ===========================================

/**
 * Sleep for specified milliseconds
 * @param {Number} ms - Milliseconds to sleep
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Format number with commas
 * @param {Number} num - Number to format
 */
function formatNumber(num) {
    return num.toLocaleString();
}

/**
 * Switch between pages
 * @param {Number} pageNumber - Page number (1 or 2)
 */
function switchPage(pageNumber) {
    // Hide all pages
    document.querySelectorAll('.page-content').forEach(page => {
        page.classList.remove('active');
    });
    
    // Show selected page
    document.getElementById(`page${pageNumber}`).classList.add('active');
    
    // Update tab active state
    document.querySelectorAll('.tab').forEach((tab, index) => {
        if (index + 1 === pageNumber) {
            tab.classList.add('active');
        } else {
            tab.classList.remove('active');
        }
    });
    
    // Log page switch
    const pageNames = ['Overview', 'Analytics', 'Data Storage', 'Retrain'];
    if (pageNumber <= 4) {
        addLog(`Switched to ${pageNames[pageNumber - 1]} page`, 'info');
    }
    
    // Handle page-specific actions
    if (pageNumber === 2) {
        // Start database analytics refresh for Analytics page
        fetchDatabaseAnalytics();
        if (dbAnalyticsInterval) clearInterval(dbAnalyticsInterval);
        dbAnalyticsInterval = setInterval(fetchDatabaseAnalytics, DB_ANALYTICS_REFRESH_INTERVAL);
    } else if (pageNumber === 3) {
        // Start auto-refresh for storage page
        refreshStorageData();
        startStorageAutoRefresh();
    } else {
        // Stop auto-refresh when leaving storage page
        stopStorageAutoRefresh();
        // Stop database analytics refresh
        if (dbAnalyticsInterval) {
            clearInterval(dbAnalyticsInterval);
            dbAnalyticsInterval = null;
        }
    }
}

// ===========================================
// Initialization
// ===========================================

/**
 * Initialize dashboard on page load
 */
window.onload = function() {
    // Initialize charts
    initCharts();
    
    // Add welcome log
    addLog('Dashboard initialized successfully!', 'success');
    addLog('Click "Start Monitoring" to begin real-time network traffic analysis', 'info');
    addLog(`Configuration: ${BATCH_SIZE} rows per batch, ${FETCH_INTERVAL/1000}s interval`, 'data');
    
    // Check if API is accessible
    checkAPIConnection();
};

/**
 * Check if API server is accessible
 */
async function checkAPIConnection() {
    try {
        const response = await fetch(`${API_BASE}/`);
        if (response.ok) {
            const data = await response.json();
            addLog(`API server connected: ${API_BASE}`, 'success');
            addLog(`Parallel processing: ${data.parallel_processing ? 'Enabled' : 'Disabled'}`, 'data');
        } else {
            addLog(`API server returned status ${response.status}`, 'error');
        }
    } catch (error) {
        addLog(`Cannot connect to API server at ${API_BASE}`, 'error');
        addLog(`Please ensure the server is running: uvicorn server:app --host 0.0.0.0 --port 8000`, 'warning');
    }
}

/**
 * Handle keyboard shortcuts
 */
document.addEventListener('keydown', function(event) {
    // Ctrl/Cmd + Enter: Start monitoring
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
        if (!isMonitoring) {
            startMonitoring();
        }
    }
    
    // Esc: Stop monitoring
    if (event.key === 'Escape') {
        if (isMonitoring) {
            stopMonitoring();
        }
    }
    
    // Number keys: Switch pages
    if (event.key === '1') {
        switchPage(1);
    }
    if (event.key === '2') {
        switchPage(2);
    }
    if (event.key === '3') {
        switchPage(3);
    }
});

// ===========================================
// Page 3: Data Storage Management
// ===========================================
// Storage page state
let currentCategory = 'benign';
let allRecords = [];
let currentPage = 1;
const RECORDS_PER_PAGE = 20;

/**
 * Switch storage category
 */
window.switchCategory = async function(category, event) {
    currentCategory = category;
    currentPage = 1;
    
    // Update active tab
    document.querySelectorAll('.category-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    if (event && event.target) {
        event.target.classList.add('active');
    } else {
        // Find and activate the correct tab by category
        const tabs = document.querySelectorAll('.category-tab');
        const categoryMap = { 'benign': 0, 'known_attacks': 1, 'unknown_dynamic': 2, 'unknown_static': 3 };
        const tabIndex = categoryMap[category];
        if (tabs[tabIndex]) {
            tabs[tabIndex].classList.add('active');
        }
    }
    
    // Load data for this category
    await loadCategoryData();
}

/**
 * Refresh all storage data
 */
async function refreshStorageData(silent = false) {
    await loadStorageStatistics();
    loadCategoryData();
    
    if (!silent) {
        console.log('Storage data refreshed');
    }
}

/**
 * Start auto-refresh for storage page
 */
function startStorageAutoRefresh() {
    // Clear any existing interval
    stopStorageAutoRefresh();
    
    // Start new interval
    storageAutoRefreshInterval = setInterval(async () => {
        await refreshStorageData(true); // Silent refresh
    }, STORAGE_REFRESH_INTERVAL);
    
    addLog(`Auto-refresh enabled (every ${STORAGE_REFRESH_INTERVAL / 1000}s)`, 'info');
}

/**
 * Stop auto-refresh
 */
function stopStorageAutoRefresh() {
    if (storageAutoRefreshInterval) {
        clearInterval(storageAutoRefreshInterval);
        storageAutoRefreshInterval = null;
    }
}

/**
 * Load storage statistics
 */
async function loadStorageStatistics() {
    try {
        const response = await fetch(`${API_BASE}/storage/statistics`);
        const data = await response.json();
        
        if (data.status === 'success') {
            const stats = data.statistics.total_records;
            document.getElementById('benignCount').textContent = stats.benign;
            document.getElementById('knownCount').textContent = stats.known_attacks;
            document.getElementById('dynamicCount').textContent = stats.unknown_dynamic;
            document.getElementById('staticCount').textContent = stats.unknown_static;
        }
    } catch (error) {
        console.error('Failed to load storage statistics:', error);
    }
}

/**
 * Load data for current category
 */
async function loadCategoryData() {
    try {
        console.log(`Loading data for category: ${currentCategory}`);
        const response = await fetch(`${API_BASE}/storage/records/${currentCategory}?limit=100&offset=0`);
        const data = await response.json();
        
        console.log(`API Response:`, data);
        console.log(`Records count: ${data.records ? data.records.length : 0}`);
        
        if (data.status === 'success') {
            allRecords = data.records || [];
            currentPage = 1;
            displayRecords();
        }
    } catch (error) {
        console.error('Failed to load category data:', error);
        allRecords = [];
        displayRecords();
    }
}

/**
 * Display records in table
 */
function displayRecords() {
    const tbody = document.getElementById('dataTableBody');
    const recordCount = document.getElementById('recordCount');
    const pageInfo = document.getElementById('pageInfo');
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    
    console.log(`Displaying records for ${currentCategory}, total: ${allRecords.length}`);
    
    // Update record count
    recordCount.textContent = `${allRecords.length} records`;
    
    // Calculate pagination
    const totalPages = Math.ceil(allRecords.length / RECORDS_PER_PAGE);
    const startIdx = (currentPage - 1) * RECORDS_PER_PAGE;
    const endIdx = startIdx + RECORDS_PER_PAGE;
    const pageRecords = allRecords.slice(startIdx, endIdx);
    
    console.log(`Page ${currentPage}/${totalPages}, showing ${pageRecords.length} records`);
    
    // Update page info
    pageInfo.textContent = totalPages > 0 ? `Page ${currentPage} of ${totalPages}` : 'No pages';
    prevBtn.disabled = currentPage <= 1;
    nextBtn.disabled = currentPage >= totalPages;
    
    // Clear table
    tbody.innerHTML = '';
    
    if (pageRecords.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5" style="text-align:center; padding:30px; color:#999;">
                    No records found in this category
                </td>
            </tr>
        `;
        return;
    }
    
    // Render records
    pageRecords.forEach((record, idx) => {
        const globalIdx = startIdx + idx;
        const row = document.createElement('tr');
        
        // Format confidence
        const confidence = (parseFloat(record.Confidence) || 0).toFixed(3);
        
        // Format timestamp
        const timestamp = new Date(record.StoredAt).toLocaleString();
        
        console.log(`Record ${idx}: Label=${record[' Label']}, Confidence=${confidence}, StoredAt=${record.StoredAt}`);
        
        // Actions based on category
        let actionsHTML = '';
        if (currentCategory === 'unknown_static') {
            actionsHTML = '<span style="color:#999; font-style:italic;">Read-only</span>';
        } else {
            actionsHTML = `<button class="btn-delete" onclick="deleteRecord(${globalIdx})">Delete</button>`;
            if (currentCategory === 'unknown_dynamic') {
                actionsHTML += `<button class="btn-relabel" onclick="openRelabelModal(${globalIdx})">Relabel</button>`;
            }
        }
        
        row.innerHTML = `
            <td>${globalIdx + 1}</td>
            <td><strong>${record[' Label']}</strong></td>
            <td>${confidence}</td>
            <td>${timestamp}</td>
            <td>${actionsHTML}</td>
        `;
        
        // Add click event to show details
        row.onclick = (e) => {
            // Don't trigger if clicking on buttons
            if (e.target.tagName === 'BUTTON') return;
            showRecordDetail(globalIdx);
        };
        
        tbody.appendChild(row);
    });
}

/**
 * Next page
 */
function nextPage() {
    const totalPages = Math.ceil(allRecords.length / RECORDS_PER_PAGE);
    if (currentPage < totalPages) {
        currentPage++;
        displayRecords();
    }
}

/**
 * Previous page
 */
function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        displayRecords();
    }
}

/**
 * Delete record
 */
async function deleteRecord(index) {
    if (!confirm('Are you sure you want to delete this record?')) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/storage/delete/${currentCategory}/${index}`, {
            method: 'DELETE'
        });
        
        const data = await response.json();
        if (data.status === 'success') {
            addLog(`Record deleted from ${currentCategory}`, 'success');
            await refreshStorageData();
        } else {
            addLog(`Failed to delete: ${data.message}`, 'error');
        }
    } catch (error) {
        addLog(`Error deleting: ${error.message}`, 'error');
    }
}

/**
 * Toggle custom input field
 */
function toggleCustomInput(value) {
    const customGroup = document.getElementById('customLabelGroup');
    const customInput = document.getElementById('customAttackLabel');
    
    if (value === 'custom') {
        customGroup.style.display = 'block';
        customInput.required = true;
    } else {
        customGroup.style.display = 'none';
        customInput.required = false;
        customInput.value = '';
    }
}

/**
 * Open relabel modal
 */
function openRelabelModal(index) {
    const record = allRecords[index];
    if (!record) {
        alert('Record not found');
        return;
    }
    // Store the record row index for relabeling
    window.currentRelabelRecord = {
        index: index,
        rowIndex: record._row_index,
        label: record[' Label']
    };
    document.getElementById('attackType').value = '';
    document.getElementById('customLabelGroup').style.display = 'none';
    document.getElementById('customAttackLabel').value = '';
    document.getElementById('relabelModal').classList.add('show');
}

/**
 * Close relabel modal
 */
function closeRelabelModal() {
    document.getElementById('relabelModal').classList.remove('show');
}

/**
 * Save relabel (move from Unknown Dynamic to Known Attacks)
 */
async function saveRelabel(event) {
    event.preventDefault();
    
    if (!window.currentRelabelRecord) {
        alert('No record selected');
        return;
    }
    
    let newLabel = document.getElementById('attackType').value;
    
    // If custom is selected, use custom input
    if (newLabel === 'custom') {
        const customLabel = document.getElementById('customAttackLabel').value.trim();
        if (!customLabel) {
            alert('Please enter a custom attack label');
            return;
        }
        newLabel = customLabel;
    }
    
    if (!newLabel) {
        alert('Please select an attack type');
        return;
    }
    
    const rowIndex = window.currentRelabelRecord.rowIndex;
    
    try {
        console.log(`Relabeling row ${rowIndex} to ${newLabel}`);
        
        // Call relabel API with row index
        const response = await fetch(`${API_BASE}/storage/relabel/${rowIndex}?new_attack_label=${encodeURIComponent(newLabel)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const data = await response.json();
        console.log('Relabel response:', data);
        
        if (data.status === 'success') {
            addLog(`Record relabeled to "${newLabel}" and moved to Known Attacks`, 'success');
            closeRelabelModal();
            
            // Remove from current view
            allRecords.splice(window.currentRelabelRecord.index, 1);
            displayRecords();
            
            // Refresh statistics
            await refreshStorageData();
        } else {
            addLog(`Failed to relabel: ${data.detail || data.message}`, 'error');
            alert(`Failed to relabel: ${data.detail || data.message}`);
        }
    } catch (error) {
        console.error('Relabel error:', error);
        addLog(`Error relabeling: ${error.message}`, 'error');
        alert(`Error: ${error.message}`);
    }
}

/**
 * Show record detail panel
 */
function showRecordDetail(index) {
    const record = allRecords[index];
    if (!record) return;
    
    const panel = document.getElementById('recordDetailPanel');
    const content = document.getElementById('detailContent');
    
    // Remove selected class from all rows
    document.querySelectorAll('.data-table tbody tr').forEach(tr => tr.classList.remove('selected'));
    
    // Add selected class to clicked row
    document.querySelectorAll('.data-table tbody tr')[index % RECORDS_PER_PAGE]?.classList.add('selected');
    
    // Build detail HTML with categorized fields
    let html = '';
    
    // Basic Information (always visible)
    html += `
        <div class="detail-category">
            <div class="category-header active" onclick="toggleCategory(this)">
                <span class="category-title"><span class="title-gradient">Basic Information</span></span>
                <span class="category-arrow">▼</span>
            </div>
            <div class="category-content show">
                <div class="detail-item">
                    <div class="detail-item-label">Label</div>
                    <div class="detail-item-value highlight">${record[' Label'] || 'N/A'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Confidence</div>
                    <div class="detail-item-value highlight">${(parseFloat(record['Confidence']) || 0).toFixed(4)}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Stored At</div>
                    <div class="detail-item-value">${new Date(record['StoredAt']).toLocaleString()}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Flow ID</div>
                    <div class="detail-item-value">${record[' Flow ID'] || 'N/A'}</div>
                </div>
            </div>
        </div>
    `;
    
    // Network Information (collapsed by default)
    html += `
        <div class="detail-category">
            <div class="category-header" onclick="toggleCategory(this)">
                <span class="category-title"><span class="title-gradient">Network Information</span></span>
                <span class="category-arrow">▶</span>
            </div>
            <div class="category-content">
                <div class="detail-item">
                    <div class="detail-item-label">Source IP</div>
                    <div class="detail-item-value">${record[' Source IP'] || 'N/A'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Source Port</div>
                    <div class="detail-item-value">${record[' Source Port'] || 'N/A'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Destination IP</div>
                    <div class="detail-item-value">${record[' Destination IP'] || 'N/A'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Destination Port</div>
                    <div class="detail-item-value">${record[' Destination Port'] || 'N/A'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Protocol</div>
                    <div class="detail-item-value">${record[' Protocol'] || 'N/A'}</div>
                </div>
            </div>
        </div>
    `;
    
    // Flow Statistics
    const flowFields = Object.keys(record).filter(k => 
        k.includes('Flow') || k.includes('Duration') || k.includes('IAT')
    );
    if (flowFields.length > 0) {
        html += `
            <div class="detail-category">
                <div class="category-header" onclick="toggleCategory(this)">
                    <span class="category-title"><span class="title-gradient">Flow Statistics</span></span>
                    <span class="category-arrow">▶</span>
                </div>
                <div class="category-content">
        `;
        flowFields.forEach(key => {
            if (!key.startsWith('_') && key !== ' Flow ID') {
                const value = typeof record[key] === 'number' ? record[key].toFixed(4) : record[key];
                html += `
                    <div class="detail-item">
                        <div class="detail-item-label">${key.trim()}</div>
                        <div class="detail-item-value">${value}</div>
                    </div>
                `;
            }
        });
        html += `</div></div>`;
    }
    
    // Packet Statistics
    const packetFields = Object.keys(record).filter(k => 
        k.includes('Packet') || k.includes('Length') || k.includes('Fwd') || k.includes('Bwd')
    );
    if (packetFields.length > 0) {
        html += `
            <div class="detail-category">
                <div class="category-header" onclick="toggleCategory(this)">
                    <span class="category-title"><span class="title-gradient">Packet Statistics</span></span>
                    <span class="category-arrow">▶</span>
                </div>
                <div class="category-content">
        `;
        packetFields.forEach(key => {
            if (!key.startsWith('_')) {
                const value = typeof record[key] === 'number' ? record[key].toFixed(4) : record[key];
                html += `
                    <div class="detail-item">
                        <div class="detail-item-label">${key.trim()}</div>
                        <div class="detail-item-value">${value}</div>
                    </div>
                `;
            }
        });
        html += `</div></div>`;
    }
    
    // Flag Statistics
    const flagFields = Object.keys(record).filter(k => 
        k.includes('Flag') || k.includes('FIN') || k.includes('SYN') || 
        k.includes('RST') || k.includes('PSH') || k.includes('ACK') || 
        k.includes('URG') || k.includes('CWE') || k.includes('ECE')
    );
    if (flagFields.length > 0) {
        html += `
            <div class="detail-category">
                <div class="category-header" onclick="toggleCategory(this)">
                    <span class="category-title"><span class="title-gradient">TCP Flags</span></span>
                    <span class="category-arrow">▶</span>
                </div>
                <div class="category-content">
        `;
        flagFields.forEach(key => {
            if (!key.startsWith('_')) {
                const value = typeof record[key] === 'number' ? record[key].toFixed(4) : record[key];
                html += `
                    <div class="detail-item">
                        <div class="detail-item-label">${key.trim()}</div>
                        <div class="detail-item-value">${value}</div>
                    </div>
                `;
            }
        });
        html += `</div></div>`;
    }
    
    // Other Fields
    const processedKeys = new Set([' Label', 'Confidence', 'StoredAt', ' Flow ID', ' Source IP', ' Source Port', 
                                   ' Destination IP', ' Destination Port', ' Protocol', ...flowFields, 
                                   ...packetFields, ...flagFields]);
    const otherFields = Object.keys(record).filter(k => !processedKeys.has(k) && !k.startsWith('_'));
    
    if (otherFields.length > 0) {
        html += `
            <div class="detail-category">
                <div class="category-header" onclick="toggleCategory(this)">
                    <span class="category-title"><span class="title-gradient">Other Statistics</span></span>
                    <span class="category-arrow">▶</span>
                </div>
                <div class="category-content">
        `;
        otherFields.forEach(key => {
            const value = typeof record[key] === 'number' ? record[key].toFixed(4) : record[key];
            html += `
                <div class="detail-item">
                    <div class="detail-item-label">${key.trim()}</div>
                    <div class="detail-item-value">${value}</div>
                </div>
            `;
        });
        html += `</div></div>`;
    }
    
    content.innerHTML = html;
    panel.classList.add('show');
}

/**
 * Toggle category collapse/expand
 */
function toggleCategory(header) {
    const content = header.nextElementSibling;
    const arrow = header.querySelector('.category-arrow');
    
    if (content.classList.contains('show')) {
        content.classList.remove('show');
        arrow.textContent = '▶';
        header.classList.remove('active');
    } else {
        content.classList.add('show');
        arrow.textContent = '▼';
        header.classList.add('active');
    }
}

/**
 * Close detail panel
 */
function closeDetailPanel() {
    const panel = document.getElementById('recordDetailPanel');
    panel.classList.remove('show');
    
    // Remove selected class from all rows
    document.querySelectorAll('.data-table tbody tr').forEach(tr => tr.classList.remove('selected'));
}

// ===========================================
// Database Analytics Functions
// ===========================================

/**
 * Fetch database analytics and update charts
 */
async function fetchDatabaseAnalytics() {
    try {
        const response = await fetch(`${API_BASE}/storage/analytics`);
        if (!response.ok) throw new Error('Failed to fetch analytics');
        
        const data = await response.json();
        updateDatabaseCharts(data);
    } catch (error) {
        console.error('Error fetching database analytics:', error);
    }
}

/**
 * Update database charts with fetched data
 */
function updateDatabaseCharts(data) {
    console.log('Updating database charts with data:', data);
    
    // Update Database Pie Chart - Label Distribution
    if (dbPieChart && data.label_distribution) {
        const labels = Object.keys(data.label_distribution);
        const values = Object.values(data.label_distribution);
        
        console.log('Pie chart - Labels:', labels, 'Values:', values);
        
        dbPieChart.data.labels = labels;
        dbPieChart.data.datasets[0].data = values;
        dbPieChart.update();
    }
    
    // Update Database Line Chart - Category Trends
    if (dbLineChart && data.label_by_category) {
        const categories = ['Benign', 'Known Attacks', 'Unknown Dynamic', 'Unknown Static'];
        
        // Get unique labels from all categories
        const allLabels = new Set();
        Object.values(data.label_by_category).forEach(categoryData => {
            Object.keys(categoryData).forEach(label => allLabels.add(label));
        });
        
        console.log('Line chart - All labels:', Array.from(allLabels));
        
        // Create datasets for each label
        const datasets = Array.from(allLabels).map((label, index) => {
            const labelData = categories.map(category => {
                const categoryKey = category.toLowerCase().replace(/ /g, '_');
                return (data.label_by_category[categoryKey] && 
                        data.label_by_category[categoryKey][label]) || 0;
            });
            
            console.log(`Dataset for ${label}:`, labelData);
            
            return {
                label: label,
                data: labelData,
                borderColor: CHART_COLORS[index % CHART_COLORS.length],
                backgroundColor: CHART_COLORS[index % CHART_COLORS.length] + '33',
                borderWidth: 2,
                tension: 0.4
            };
        });
        
        dbLineChart.data.labels = categories;
        dbLineChart.data.datasets = datasets;
        dbLineChart.update();
        
        console.log('Line chart updated with', datasets.length, 'datasets');
    }
}

// ===========================================
// Page 4: Retrain Model Functions
// ===========================================

/**
 * Start immediate retrain process
 */
function startImmediateRetrain() {
    const button = document.getElementById('immediateRetrainBtn');
    const loading = document.getElementById('immediateRetrainLoading');
    const success = document.getElementById('immediateRetrainSuccess');
    
    // Hide button and success message
    button.style.display = 'none';
    success.style.display = 'none';
    
    // Show loading animation
    loading.style.display = 'block';
    
    // Simulate retrain progress
    let progress = 0;
    const progressFill = document.getElementById('immediateProgress');
    const progressText = document.getElementById('immediateProgressText');
    
    const interval = setInterval(() => {
        progress += Math.random() * 15;
        if (progress > 100) progress = 100;
        
        progressFill.style.width = progress + '%';
        progressText.textContent = Math.floor(progress) + '%';
        
        if (progress >= 100) {
            clearInterval(interval);
            setTimeout(() => {
                loading.style.display = 'none';
                success.style.display = 'block';
                
                // Show button again after 5 seconds
                setTimeout(() => {
                    success.style.display = 'none';
                    button.style.display = 'block';
                }, 5000);
            }, 500);
        }
    }, 300);
}

/**
 * Start scheduled retrain process
 */
function startScheduledRetrain() {
    // Get input values
    const hour = document.getElementById('scheduleHour').value;
    const minute = document.getElementById('scheduleMinute').value;
    const day = document.getElementById('scheduleDay').value;
    const month = document.getElementById('scheduleMonth').value;
    const year = document.getElementById('scheduleYear').value;
    const cycle = document.getElementById('scheduleCycle').value;
    const customDays = document.getElementById('customCycleDays').value;
    
    // Validation
    if (!cycle) {
        alert('Vui lòng chọn chu kỳ Retrain!');
        return;
    }
    
    if (cycle === 'custom' && !customDays) {
        alert('Vui lòng nhập số ngày cho chu kỳ tùy chọn!');
        return;
    }
    
    // Get elements
    const button = document.getElementById('scheduleRetrainBtn');
    const loading = document.getElementById('scheduledRetrainLoading');
    const success = document.getElementById('scheduledRetrainSuccess');
    const successMessage = document.getElementById('scheduledSuccessMessage');
    const scheduleInfo = document.getElementById('currentScheduleInfo');
    const scheduleDetails = document.getElementById('scheduleDetails');
    
    // Hide elements
    button.style.display = 'none';
    success.style.display = 'none';
    scheduleInfo.style.display = 'none';
    
    // Show loading
    loading.style.display = 'block';
    
    // Simulate setup progress
    let progress = 0;
    const progressFill = document.getElementById('scheduledProgress');
    const progressText = document.getElementById('scheduledProgressText');
    
    const interval = setInterval(() => {
        progress += Math.random() * 20;
        if (progress > 100) progress = 100;
        
        progressFill.style.width = progress + '%';
        progressText.textContent = Math.floor(progress) + '%';
        
        if (progress >= 100) {
            clearInterval(interval);
            
            // Determine cycle text
            let cycleText = '';
            switch(cycle) {
                case 'weekly':
                    cycleText = 'hàng tuần';
                    break;
                case 'monthly':
                    cycleText = 'hàng tháng';
                    break;
                case 'yearly':
                    cycleText = 'hàng năm';
                    break;
                case 'custom':
                    cycleText = `mỗi ${customDays} ngày`;
                    break;
            }
            
            setTimeout(() => {
                loading.style.display = 'none';
                
                // Show success message
                successMessage.textContent = `Hệ thống sẽ tự động được Retrain theo chu kỳ ${cycleText}.`;
                success.style.display = 'block';
                
                // Show schedule info
                scheduleDetails.innerHTML = `
                    <strong>Thời gian bắt đầu:</strong> ${hour.padStart(2, '0')}:${minute.padStart(2, '0')} - ${day}/${month}/${year}<br>
                    <strong>Chu kỳ:</strong> ${cycleText}<br>
                    <strong>Trạng thái:</strong> <span style="color: #28a745; font-weight: 600;"><span class="status-active"></span> Đã kích hoạt</span>
                `;
                scheduleInfo.style.display = 'block';
                
                // Show button again after 3 seconds
                setTimeout(() => {
                    button.style.display = 'block';
                }, 3000);
            }, 500);
        }
    }, 200);
}

/**
 * Toggle custom cycle input
 */
function toggleCustomCycle(value) {
    const customGroup = document.getElementById('customCycleGroup');
    if (value === 'custom') {
        customGroup.style.display = 'block';
    } else {
        customGroup.style.display = 'none';
    }
}

// ===========================================
// Export functions for HTML onclick handlers
// ===========================================
window.startMonitoring = startMonitoring;
window.stopMonitoring = stopMonitoring;
window.switchPage = switchPage;
window.nextPage = nextPage;
window.prevPage = prevPage;
window.deleteRecord = deleteRecord;
window.openRelabelModal = openRelabelModal;
window.closeRelabelModal = closeRelabelModal;
window.toggleCustomInput = toggleCustomInput;
window.saveRelabel = saveRelabel;
window.showRecordDetail = showRecordDetail;
window.closeDetailPanel = closeDetailPanel;
window.toggleCategory = toggleCategory;
window.startImmediateRetrain = startImmediateRetrain;
window.startScheduledRetrain = startScheduledRetrain;
window.toggleCustomCycle = toggleCustomCycle;





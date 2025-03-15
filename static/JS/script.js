const attackTypesChart = new Chart(document.getElementById('attackTypesChart'), {
    type: 'pie',
    data: {
        labels: [
                'Application Layer Attack', 
                'Transport Layer', 
                'Network Layer Attack', 
                'Data Link layer', 
                'Physical Layer'
            ],
        datasets: [{
            data: [1, 3, 4, 5, 6], 
            backgroundColor: ['#FFFF00', '#FFA500','#008000', '#0000FF', '#FF0000'],
        }]
    }
});

const attackFrequencyChart = new Chart(document.getElementById('attackFrequencyChart'), {
    type: 'line',
    data: {
        labels: ['2023-10-15', '2023-10-16', '2023-10-17', '2023-10-18', '2023-10-19','2023-10-20'],
        datasets: [{
            label: 'Attacks',
            data: [3, 1, 2, 2, 5, 0], 
            borderColor: '#36A2EB',
            fill: true,
        }]
    },
    options: {
        scales: {
            y: {
                beginAtZero: true
            }
        }
    }
});

function updateDashboard() {
    document.getElementById('total-alerts').textContent = alerts.length;
    document.getElementById('top-source-ip').textContent = "192.168.1.100";
    document.getElementById('top-target-ip').textContent = "192.168.1.200";
}

document.getElementById('search-alerts').addEventListener('input', (event) => {
    const searchTerm = event.target.value.toLowerCase();
    const rows = document.querySelectorAll('#alerts-table tbody tr');
    rows.forEach(row => {
        const cells = row.getElementsByTagName('td');
        let match = false;
        for (let cell of cells) {
            if (cell.textContent.toLowerCase().includes(searchTerm)) {
                match = true;
                break;
            }
        }
        row.style.display = match ? '' : 'none';
    });
});

function sortTable(columnIndex) {
    const table = document.getElementById('alerts-table');
    const rows = Array.from(table.querySelectorAll('tbody tr'));
    const isAscending = table.getAttribute('data-sort-asc') === 'true';

    rows.sort((a, b) => {
        const aValue = a.getElementsByTagName('td')[columnIndex].textContent;
        const bValue = b.getElementsByTagName('td')[columnIndex].textContent;
        return isAscending ? aValue.localeCompare(bValue) : bValue.localeCompare(aValue);
    });

    table.setAttribute('data-sort-asc', !isAscending);
    table.querySelector('tbody').innerHTML = '';
    rows.forEach(row => table.querySelector('tbody').appendChild(row));
}


updateDashboard();
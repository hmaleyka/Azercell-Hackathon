// Example data and configuration for a pie chart
const labels = ['Red', 'Green', ];
const data = {
    labels: labels,
    datasets: [{
        label: 'My First Dataset',
        data: [300, 50, 100, 60, 80, 90],
        backgroundColor: [
            'rgb(255, 99, 132)',
            'rgb(73, 85, 61)',
            
        ],
        hoverOffset: 4
    }]
};

const config = {
    type: 'pie',
    data: data,
    options: {
        responsive: true,
        plugins: {
            legend: {
                position: 'top',
                labels: {
                    color: 'white' // Set the legend labels to white
                }
            },
            title: {
                display: true,
                text: ' Pie Chart',
                color:  'white'
                
            }
        }
    },
};

// Render the chart
const myPieChart = new Chart(
    document.getElementById('myPieChart'),
    config
);




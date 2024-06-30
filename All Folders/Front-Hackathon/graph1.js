// <block:actions:2>
const actions = [
    {
      name: 'Stacked: true',
      handler: (chart) => {
        chart.options.scales.y.stacked = true;
        chart.update();
      }
    },
    {
      name: 'Stacked: false (default)',
      handler: (chart) => {
        chart.options.scales.y.stacked = false;
        chart.update();
      }
    },
    {
      name: 'Stacked Single',
      handler: (chart) => {
        chart.options.scales.y.stacked = 'single';
        chart.update();
      }
    },
    {
      name: 'Randomize',
      handler(chart) {
        chart.data.datasets.forEach(dataset => {
    
        });
        chart.update();
      }
    },
    {
      name: 'Add Dataset',
      handler(chart) {
        const data = chart.data;
       
        const newDataset = {
          label: 'Dataset ' + (data.datasets.length + 1),
          backgroundColor: dsColor,
          borderColor: dsColor,
          fill: true,
         
        };
        chart.data.datasets.push(newDataset);
        chart.update();
      }
    },
    {
      name: 'Add Data',
      handler(chart) {
        const data = chart.data;
        if (data.datasets.length > 0) {
          
  
          for (let index = 0; index < data.datasets.length; ++index) {
           
          }
  
          chart.update();
        }
      }
    },
    {
      name: 'Remove Dataset',
      handler(chart) {
        chart.data.datasets.pop();
        chart.update();
      }
    },
    {
      name: 'Remove Data',
      handler(chart) {
        chart.data.labels.splice(-1, 1); // remove the label first
  
        chart.data.datasets.forEach(dataset => {
          dataset.data.pop();
        });
  
        chart.update();
      }
    }
  ];
  // </block:actions>
  
  // <block:setup:1>
  const DATA_COUNT = 7;
  const NUMBER_CFG = {count: DATA_COUNT, min: -100, max: 100};
  
  
  const data5 = {
   
    datasets: [
      {
        label: 'My First dataset',
       
        fill: true
      },
      {
        label: 'My Second dataset',
        
        fill: true
      },
      {
        label: 'My Third dataset',
       
        fill: true
      },
      {
        label: 'My Fourth dataset',
     
        fill: true
      }
    ]
  };
  // </block:setup>
  
  // <block:config:0>
  const config5 = {
    type: 'line',
    data: data5,
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: (ctx) => 'Chart.js Line Chart - stacked=' + ctx.chart.options.scales.y.stacked
        },
        tooltip: {
          mode: 'index'
        },
      },
      interaction: {
        mode: 'nearest',
        axis: 'x',
        intersect: false
      },
      scales: {
        x: {
          title: {
            display: true,
            text: 'Month'
          }
        },
        y: {
          stacked: true,
          title: {
            display: true,
            text: 'Value'
          }
        }
      }
    }
  };
  // </block:config>
  
 

  const myGraphChart = new Chart(
    document.getElementById('myGraphChart'),
    config5
);
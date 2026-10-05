/*
============================================================
 AI Kubernetes Runtime Security Dashboard
 Animated Security Charts
 Chart.js Integration
============================================================
*/


let timelineChart = null;
let threatChart = null;



document.addEventListener(
    "DOMContentLoaded",
    () => {

        initializeCharts();


        setInterval(

            updateCharts,

            5000

        );

    }
);





/*
============================================================
 INITIALIZE CHARTS
============================================================
*/


function initializeCharts(){


    const timeline = document.getElementById(
        "timelineChart"
    );


    const pie = document.getElementById(
        "pieChart"
    );



    if(timeline){


        timelineChart = new Chart(

            timeline,

            {

                type:"line",


                data:{


                    labels:[],


                    datasets:[

                        {


                            label:"Security Events",


                            data:[],


                            borderWidth:3,


                            tension:.4,


                            fill:true,


                            backgroundColor:

                            "rgba(34,211,238,0.12)",


                            borderColor:

                            "#22d3ee",


                            pointBackgroundColor:

                            "#22d3ee"



                        }

                    ]


                },



                options:{


                    responsive:true,


                    animation:{


                        duration:800,


                        easing:"easeOutQuart"


                    },


                    plugins:{


                        legend:{


                            labels:{


                                color:"#94a3b8"


                            }


                        }


                    },



                    scales:{


                        x:{


                            ticks:{


                                color:"#64748b"


                            },


                            grid:{


                                color:

                                "rgba(255,255,255,.05)"


                            }


                        },


                        y:{


                            ticks:{


                                color:"#64748b"


                            },


                            grid:{


                                color:

                                "rgba(255,255,255,.05)"


                            }


                        }



                    }


                }



            }

        );


    }





    if(pie){



        threatChart = new Chart(

            pie,


            {


                type:"doughnut",


                data:{


                    labels:[

                        "Killed",

                        "Isolated",

                        "Resource Alerts"

                    ],



                    datasets:[{


                        data:[0,0,0],



                        backgroundColor:[


                            "#ef4444",

                            "#f59e0b",

                            "#22c55e"


                        ],


                        borderWidth:0


                    }]


                },


                options:{


                    responsive:true,


                    cutout:"70%",


                    animation:{


                        animateRotate:true,


                        duration:1000


                    },



                    plugins:{


                        legend:{


                            position:"bottom",



                            labels:{


                                color:"#94a3b8",

                                padding:20


                            }


                        }


                    }


                }


            }

        );

    }


}






/*
============================================================
 UPDATE CHART DATA
============================================================
*/


function updateCharts(){


    const incidents = getIncidents();


    const stats = getStats();



    updateTimeline(

        incidents

    );



    updateThreatDistribution(

        stats

    );


}







/*
============================================================
 THREAT TIMELINE
============================================================
*/


function updateTimeline(incidents){



    if(!timelineChart)

        return;



    const grouped = {};



    incidents.forEach(

        incident => {


            const time =

            incident.timestamp

            ?

            new Date(

                incident.timestamp

            )

            .toLocaleTimeString()

            :

            "unknown";



            if(!grouped[time])

                grouped[time]=0;



            grouped[time]++;


        }

    );




    const labels =

        Object.keys(grouped)

        .slice(-15);



    const values =

        labels.map(

            l=>grouped[l]

        );



    timelineChart.data.labels = labels;


    timelineChart.data.datasets[0].data = values;



    timelineChart.update();


}







/*
============================================================
 THREAT DISTRIBUTION
============================================================
*/


function updateThreatDistribution(stats){



    if(!threatChart)

        return;



    threatChart.data.datasets[0].data = [


        stats.killed || 0,


        stats.isolated || 0,


        stats.resource_alerts || 0


    ];



    threatChart.update();


}

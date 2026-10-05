/*
============================================================
 AI Kubernetes Runtime Security Dashboard
 API Communication Layer
============================================================
*/


const API_ENDPOINT = "/api/incidents";



/*
    Global dashboard state

    Other JS files can access this:
    dashboard.js
    charts.js
*/

const DashboardState = {

    incidents: [],

    stats: {

        total_events:0,

        killed:0,

        isolated:0,

        resource_alerts:0,

        circuit_breaker_blocks:0,

        pods_affected:0

    },

    lastUpdate:null

};





/*
============================================================
 FETCH INCIDENT DATA
============================================================
*/


async function fetchIncidents(){


    try {


        const response = await fetch(API_ENDPOINT, {


            method:"GET",

            headers:{


                "Accept":"application/json"


            }


        });



        if(!response.ok){


            throw new Error(

                `API Error ${response.status}`

            );


        }



        const data = await response.json();



        DashboardState.incidents = data.incidents || [];

        DashboardState.stats = data.stats || {};

        DashboardState.lastUpdate = data.server_time;



        updateConnectionStatus(true);



        return data;



    }

    catch(error){



        console.error(

            "Dashboard API error:",

            error

        );



        updateConnectionStatus(false);



        return null;


    }


}





/*
============================================================
 CONNECTION STATUS
============================================================
*/


function updateConnectionStatus(online){



    const status = document.getElementById(

        "last-updated"

    );



    if(!status)

        return;



    if(online){



        const time = new Date()

            .toLocaleTimeString();



        status.innerHTML =

        `LIVE · ${time}`;



        status.style.color =

            "#22c55e";



    }

    else {



        status.innerHTML =

            "CONNECTION LOST";



        status.style.color =

            "#ef4444";


    }


}






/*
============================================================
 AUTO REFRESH ENGINE
============================================================
*/


function startRealtimeUpdates(){


    // first load

    fetchIncidents();



    // refresh every 5 seconds

    setInterval(()=>{


        fetchIncidents();


    },5000);



}





/*
============================================================
 HELPERS
============================================================
*/


function getIncidents(){


    return DashboardState.incidents;


}



function getStats(){


    return DashboardState.stats;


}

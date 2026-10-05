/*
============================================================
 AI Kubernetes Runtime Security Dashboard
 Main Dashboard Controller
============================================================
*/


document.addEventListener(
    "DOMContentLoaded",
    () => {

        startRealtimeUpdates();

        setInterval(
            renderDashboard,
            1000
        );

    }
);





/*
============================================================
 UPDATE EVERYTHING
============================================================
*/


function renderDashboard(){


    const stats = getStats();


    updateCounters(stats);


    renderIncidents(
        getIncidents()
    );


    updateAISummary(
        getIncidents()
    );


}






/*
============================================================
 KPI COUNTERS
============================================================
*/


function updateCounters(stats){



    animateNumber(

        "totalEvents",

        stats.total_events || 0

    );



    animateNumber(

        "killedPods",

        stats.killed || 0

    );



    animateNumber(

        "isolatedPods",

        stats.isolated || 0

    );



    animateNumber(

        "resourceAlerts",

        stats.resource_alerts || 0

    );



    animateNumber(

        "breakerBlocks",

        stats.circuit_breaker_blocks || 0

    );



}







/*
============================================================
 NUMBER ANIMATION
============================================================
*/


const previousValues = {};



function animateNumber(id,value){


    const element = document.getElementById(id);



    if(!element)

        return;



    if(previousValues[id] === value)

        return;



    previousValues[id]=value;



    let start = 0;



    const duration = 600;


    const startTime = performance.now();




    function update(time){



        const progress = Math.min(

            (time-startTime)/duration,

            1

        );



        const current = Math.floor(

            progress * value

        );



        element.innerText=current;



        if(progress < 1){


            requestAnimationFrame(update);


        }



    }



    requestAnimationFrame(update);


}







/*
============================================================
 INCIDENT RENDERING
============================================================
*/


function renderIncidents(incidents){



    const container =

        document.getElementById(

            "incidentList"

        );



    if(!container)

        return;



    if(!incidents || incidents.length===0){


        container.innerHTML = `

        <div class="empty">

            <i class="ti ti-shield-check"></i>

            <p>No active threats detected</p>

        </div>

        `;


        return;


    }





    container.innerHTML = incidents

    .slice(0,20)

    .map(

        incident => {



            const action =

                incident.action || "unknown";



            const cssClass =

                getThreatClass(action);




            return `

            <div class="incident ${cssClass}">


                <div class="incident-title">


                    <strong>

                    ${incident.pod_name || "unknown"}

                    </strong>



                    <span class="badge">

                    ${action}

                    </span>


                </div>



                <div class="incident-meta">


                    Namespace:

                    <b>

                    ${incident.namespace || "N/A"}

                    </b>


                    <br>


                    Rule:

                    <b>

                    ${incident.triggering_rule || "N/A"}

                    </b>


                    <br>


                    Priority:

                    <b>

                    ${incident.triggering_priority || "N/A"}

                    </b>


                </div>




                ${
                    incident.anomaly_score !== null

                    ?

                    `

                    <div class="score">

                    Isolation Forest Score:

                    <b>

                    ${incident.anomaly_score}

                    </b>

                    </div>

                    `

                    :

                    ""

                }





                ${
                    incident.summary

                    ?

                    `

                    <div class="ai-report">


                    <i class="ti ti-robot"></i>

                    ${incident.summary}


                    </div>

                    `

                    :

                    ""

                }



            </div>

            `;


        }

    )

    .join("");



}







/*
============================================================
 THREAT COLORS
============================================================
*/


function getThreatClass(action){


    if(action==="kill")

        return "kill";



    if(action==="isolate")

        return "isolate";



    if(action==="resource_alert")

        return "resource_alert";



    if(

        action &&

        action.includes(

            "circuit_breaker"

        )

    )

        return "blocked";



    return "";

}






/*
============================================================
 AI SUMMARY PANEL
============================================================
*/


function updateAISummary(incidents){



    const box =

        document.getElementById(

            "aiSummary"

        );



    if(!box)

        return;



    const latest = incidents[0];



    if(!latest){


        box.innerHTML =

        "Waiting for security event...";


        return;


    }




    if(latest.summary){


        box.innerHTML = `

        <div class="ai-content">

        <i class="ti ti-brain"></i>


        ${latest.summary}


        </div>

        `;


    }

    else {


        box.innerHTML = `

        <div>

        <i class="ti ti-loader"></i>

        Waiting for LLM analysis...

        </div>

        `;


    }



}

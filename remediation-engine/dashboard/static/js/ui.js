/*
============================================================
 AI Kubernetes Runtime Security Dashboard
 UI Interaction Layer
============================================================
*/


document.addEventListener(
    "DOMContentLoaded",
    () => {


        initializeUI();


    }
);





/*
============================================================
 INITIAL UI SETUP
============================================================
*/


function initializeUI(){


    createMobileMenu();


    addHoverEffects();


    enableIncidentAnimation();


}






/*
============================================================
 MOBILE SIDEBAR MENU
============================================================
*/


function createMobileMenu(){



    const sidebar = document.querySelector(

        ".sidebar"

    );



    if(!sidebar)

        return;




    const button = document.createElement(

        "button"

    );



    button.className = "mobile-menu";



    button.innerHTML =

    `

    <i class="ti ti-menu-2"></i>

    `;



    document.body.appendChild(button);





    button.addEventListener(

        "click",

        ()=>{


            sidebar.classList.toggle(

                "active"

            );


        }

    );



}







/*
============================================================
 CLOSE SIDEBAR WHEN CLICKING OUTSIDE
============================================================
*/


document.addEventListener(

    "click",

    (event)=>{


        const sidebar =

        document.querySelector(

            ".sidebar"

        );



        const menu =

        document.querySelector(

            ".mobile-menu"

        );



        if(

            sidebar &&

            sidebar.classList.contains(

                "active"

            )

            &&

            !sidebar.contains(event.target)

            &&

            !menu.contains(event.target)

        ){


            sidebar.classList.remove(

                "active"

            );


        }


    }

);







/*
============================================================
 SIDEBAR ACTIVE PAGE
============================================================
*/


document

.querySelectorAll(

    ".sidebar nav a"

)

.forEach(

    link=>{


        link.addEventListener(

            "click",

            ()=>{


                document

                .querySelectorAll(

                    ".sidebar nav a"

                )

                .forEach(

                    item=>{

                        item.classList.remove(

                            "active"

                        );

                    }

                );



                link.classList.add(

                    "active"

                );


            }

        );


    }

);







/*
============================================================
 INCIDENT ANIMATION
============================================================
*/


function enableIncidentAnimation(){



    const observer = new MutationObserver(

        mutations=>{


            mutations.forEach(

                mutation=>{


                    mutation.addedNodes

                    .forEach(

                        node=>{


                            if(

                                node.nodeType===1

                                &&

                                node.classList.contains(

                                    "incident"

                                )

                            ){


                                node.style.animation =

                                "incidentSlide .45s ease";


                            }


                        }

                    );


                }

            );


        }

    );



    const container =

        document.getElementById(

            "incidentList"

        );



    if(container){


        observer.observe(

            container,

            {

                childList:true

            }

        );


    }



}








/*
============================================================
 CARD HOVER SECURITY EFFECTS
============================================================
*/


function addHoverEffects(){



    document

    .querySelectorAll(

        ".card"

    )

    .forEach(

        card=>{


            card.addEventListener(

                "mouseenter",

                ()=>{


                    card.style.transform =

                    "translateY(-8px) scale(1.02)";


                }

            );



            card.addEventListener(

                "mouseleave",

                ()=>{


                    card.style.transform =

                    "";


                }

            );


        }

    );

}








/*
============================================================
 LIVE CLOCK
============================================================
*/


function updateClock(){



    const clock =

    document.getElementById(

        "last-updated"

    );



    if(!clock)

        return;



    if(

        DashboardState.lastUpdate

    ){


        clock.innerHTML =

        `LIVE · ${new Date()

        .toLocaleTimeString()}`;


    }



}



setInterval(

    updateClock,

    1000

);

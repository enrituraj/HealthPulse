const toggle = document.getElementById("menu_toggle");
        const toggle2 = document.getElementById("menu_toggle2");
        const menu = document.getElementById("menu");

        toggle.addEventListener("click",()=>{
            menu.classList.toggle('active')
        })
        toggle2.addEventListener("click",()=>{
            
            menu.classList.toggle('active')
        })
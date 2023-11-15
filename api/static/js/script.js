const toggle = document.getElementById("menu_toggle");
const toggle2 = document.getElementById("menu_toggle2");
const menu = document.getElementById("menu");

toggle.addEventListener("click", () => {
    menu.classList.toggle('active')
})
toggle2.addEventListener("click", () => {

    menu.classList.toggle('active')
})

document.addEventListener("click", e => {
    const isDropdownButton = e.target.closest("[data-dropdown-button]")
    if (!isDropdownButton && e.target.closest("[data-dropdown]") != null) return
  
    let currentDropdown
    if (isDropdownButton) {
      currentDropdown = e.target.closest("[data-dropdown]")
      currentDropdown.classList.toggle("active")
    }
  
    document.querySelectorAll("[data-dropdown].active").forEach(dropdown => {
      if (dropdown === currentDropdown) return
      dropdown.classList.remove("active")
    })
  })
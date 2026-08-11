const toggle = document.querySelector(".menu-toggle");
const links = document.querySelector(".nav-links");
if (toggle) {
  toggle.addEventListener("click", () => links.classList.toggle("open"));
}
document.querySelectorAll(".nav-links a").forEach(a => {
  a.addEventListener("click", () => links && links.classList.remove("open"));
});

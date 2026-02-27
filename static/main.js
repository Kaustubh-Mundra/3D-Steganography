function copyKey() {
    const key = document.getElementById("secretKey").innerText;
    navigator.clipboard.writeText(key);

    const toast = document.getElementById("toast");
    toast.classList.add("show");

    setTimeout(() => {
        toast.classList.remove("show");
    }, 2000);
}
function showLoader() {
    document.getElementById("loader").style.display = "block";
}

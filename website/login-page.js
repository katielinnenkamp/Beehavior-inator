const loginForm = document.getElementById("login");
const loginButton = document.getElementById("login-button")

loginButton.addEventListener("click", (e) => {
    e.preventDefault();
    const username = loginForm.username.value;
    var t = new Date();
    var time = t.getTime();

    /* insert hooks here for data collection
     - username provided
     - eventually password if we add it the form
     - timestamp
     - browser
     - ip
    
    */

    //maybe somewhat proper sanitization unless we want to give the professor heartburn
    if (username === "admin") {
        alert("slay you got in (this is temp message)");
        location.reload();

    } else {
        window.open("https://www.youtube.com/watch?v=bgJ_1WuhUig", "_blank");
    }
})
// API conf
const API_BASE = (function () {
    if (window.API_BASE_OVERRIDE) return window.API_BASE_OVERRIDE;
    const host = window.location.hostname;
    if (host === "localhost" || host === "127.0.0.1") {
        return "http://localhost:8000/api/v1";
    }
    // Production backend on Render
    return "https://vms-backend-h4r4.onrender.com/api/v1";
}) ();
//store token 
function saveToken(token) {
    localStorage.setItem("access_token", token);
}

//get the token
function getToken(){
    return localStorage.getItem("access_token");
}

//remove token and role (logout) - clears everything so next user starts fresh
function clearToken(){
    localStorage.removeItem("access_token");
    localStorage.removeItem("user_role");
}

//authenticating api request
async function apiRequest(endpoint, method="GET", body = null){
    const headers = {
        "Content-Type": "application/json",
    };
    const token = getToken();
    if(token){
        headers["Authorization"]= `Bearer ${token}`;
    }

    const options={method, headers};
    if (body){
        options.body = JSON.stringify(body);
    }

    const response = await fetch (`${API_BASE}${endpoint}`, options);

    if (response.status ===401){
        clearToken();
        window.location.href="login.html";
        return null; 
    }

    return response;

}


//login using form data and not JSON
async function login (username, password){
    const formData = new URLSearchParams();
    formData.append("username", username);
    formData.append("password", password);

    const response = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: formData,
    });
    return response;
}


//Auth check is user logged in, if not redirect to login
function requireAuth(){
    if(!getToken()){
        window.location.href="login.html";
    }
}

//get the logged-in user's role - used to show/hide UI elements per role
function getUserRole(){
    return localStorage.getItem("user_role");
}

//hiding elements that don't apply to the current user's role
function applyRoleVisibility(){
    const role = getUserRole();

    
    if(role === "guard"){
        const reportsLink = document.querySelector('a[href="reports.html"]');
        if(reportsLink) reportsLink.parentElement.style.display = "none";
    }
    if(role !== "admin"){
        const usersLink = document.querySelector('a[href="users.html"]');
        if(usersLink) usersLink.parentElement.style.display = "none";
    }
}


//format a UTC timestamp from the api as kenyan time (EAT, UTC+3)
function formatKenyaTime(utcString){
    if(!utcString) return "";
    //the api sends naive utc timestamps, so mark them as utc (append Z) if no timezone is present
    const iso = (utcString.endsWith("Z") || utcString.includes("+")) ? utcString : utcString + "Z";
    return new Date(iso).toLocaleString("en-KE", {
        timeZone: "Africa/Nairobi",
        dateStyle: "medium",
        timeStyle: "short",
    });
}
